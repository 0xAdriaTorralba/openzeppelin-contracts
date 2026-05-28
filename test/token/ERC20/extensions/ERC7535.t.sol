// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC7535} from "@openzeppelin/contracts/token/ERC20/extensions/ERC7535.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @dev Concrete deployable ERC7535 vault with a configurable decimals offset.
contract ERC7535VaultMock is ERC7535 {
    uint8 private immutable _offset;

    constructor(uint8 offset_) ERC20("Native Vault", "nVLT") {
        _offset = offset_;
    }

    function _decimalsOffset() internal view virtual override returns (uint8) {
        return _offset;
    }
}

/// @dev Malicious share owner / receiver that attempts to reenter the vault on the ETH `sendValue` callback.
///
/// With the CEI-only design (no reentrancy guard), the reentrant call is NOT itself blocked by a guard. Instead
/// this receiver is used to observe the vault's state *during* the outbound ETH push and to attempt a second,
/// full-amount redeem of the very shares that triggered the payout. The point of the tests is to prove that
/// checks-effects-interactions makes such a reentry harmless: the shares are already burned when the callback
/// fires, so the receiver cannot extract more than its shares entitled it to, and cannot drain other users.
contract ReentrantReceiver {
    enum Kind {
        None,
        Withdraw,
        Redeem
    }

    ERC7535VaultMock public vault;
    Kind public kind;
    uint256 public reenterShares; // shares the receiver tries to re-redeem during the callback

    bool public reentered;
    bool public reentryReverted;

    // State snapshot observed *inside* the reentrant callback (i.e. mid-`_withdraw`, after the burn).
    uint256 public observedSelfBalance;
    uint256 public observedTotalSupply;

    function setup(ERC7535VaultMock vault_, Kind kind_, uint256 reenterShares_) external {
        vault = vault_;
        kind = kind_;
        reenterShares = reenterShares_;
    }

    receive() external payable {
        if (kind == Kind.None) return;
        reentered = true;

        // Observe the vault state as seen by a reentrant party during the ETH push.
        observedSelfBalance = vault.balanceOf(address(this));
        observedTotalSupply = vault.totalSupply();

        // Attempt to re-extract the *same* shares again, mid-payout. CEI must make this fail (the shares were
        // already burned) or otherwise be unable to over-drain. We swallow the revert so the outer call can
        // complete and the test can assert the resulting accounting.
        try this.reenter() {
            reentryReverted = false;
        } catch {
            reentryReverted = true;
        }
    }

    function reenter() external {
        if (kind == Kind.Withdraw) {
            vault.withdraw(reenterShares, address(this), address(this));
        } else if (kind == Kind.Redeem) {
            vault.redeem(reenterShares, address(this), address(this));
        }
    }
}

contract ERC7535Test is Test {
    uint256 internal constant MAX_ETH = 1e27; // ~1B ETH worth of wei, keeps fuzz inputs realistic

    ERC7535VaultMock internal vault;

    address internal attacker = makeAddr("attacker");
    address internal victim = makeAddr("victim");
    address internal other = makeAddr("other");

    receive() external payable {}

    function setUp() public {
        vault = new ERC7535VaultMock(0);
    }

    // --------------------------------------------------------------------------------------------
    // Metadata / asset semantics
    // --------------------------------------------------------------------------------------------

    function testAssetSentinel() public view {
        assertEq(vault.asset(), 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);
    }

    function testFuzzDecimals(uint8 offset) public {
        offset = uint8(bound(offset, 0, 30));
        ERC7535VaultMock v = new ERC7535VaultMock(offset);
        assertEq(v.decimals(), uint256(18) + offset);
    }

    function testTotalAssetsTracksBalance() public {
        assertEq(vault.totalAssets(), 0);
        vm.deal(address(vault), 5 ether);
        assertEq(vault.totalAssets(), 5 ether);
    }

    // --------------------------------------------------------------------------------------------
    // msg.value enforcement
    // --------------------------------------------------------------------------------------------

    function testFuzzDepositRevertsOnValueMismatch(uint256 assets, uint256 value) public {
        assets = bound(assets, 0, MAX_ETH);
        value = bound(value, 0, MAX_ETH);
        vm.assume(assets != value);
        vm.deal(address(this), value);
        vm.expectRevert(abi.encodeWithSelector(ERC7535.ERC7535UnexpectedDepositValue.selector, value, assets));
        vault.deposit{value: value}(assets, victim);
    }

    function testFuzzMintRevertsOnValueMismatch(uint256 shares, uint256 value) public {
        shares = bound(shares, 1, MAX_ETH);
        uint256 cost = vault.previewMint(shares); // empty vault, queried before sending value
        value = bound(value, 0, MAX_ETH);
        vm.assume(value != cost);
        vm.deal(address(this), value);
        vm.expectRevert(abi.encodeWithSelector(ERC7535.ERC7535UnexpectedMintValue.selector, value, cost));
        vault.mint{value: value}(shares, victim);
    }

    // --------------------------------------------------------------------------------------------
    // previewDeposit (queried standalone, before value is sent) == shares actually minted
    // This is the msg.value / totalAssets correctness property.
    // --------------------------------------------------------------------------------------------

    function testFuzzPreviewDepositEqualsMinted(uint256 seed, uint256 assets) public {
        // Seed the vault with some real balance and supply so totalAssets() and totalSupply() are non-trivial.
        seed = bound(seed, 0, MAX_ETH);
        if (seed != 0) {
            vm.deal(address(this), seed);
            vault.deposit{value: seed}(seed, other);
        }

        assets = bound(assets, 0, MAX_ETH);

        // Off-chain preview MUST be computed before sending value (view cannot see in-flight msg.value).
        uint256 previewed = vault.previewDeposit(assets);

        vm.deal(attacker, assets);
        vm.prank(attacker);
        uint256 minted = vault.deposit{value: assets}(assets, attacker);

        assertEq(minted, previewed, "previewDeposit != minted shares");
        assertEq(vault.balanceOf(attacker), previewed);
    }

    function testFuzzPreviewMintEqualsActualCost(uint256 seed, uint256 shares) public {
        seed = bound(seed, 0, MAX_ETH);
        if (seed != 0) {
            vm.deal(address(this), seed);
            vault.deposit{value: seed}(seed, other);
        }

        shares = bound(shares, 0, 1e24);
        uint256 cost = vault.previewMint(shares);
        vm.assume(cost <= MAX_ETH);

        vm.deal(attacker, cost);
        vm.prank(attacker);
        uint256 actual = vault.mint{value: cost}(shares, attacker);

        assertEq(actual, cost, "mint returned assets != previewMint");
        assertEq(vault.balanceOf(attacker), shares);
    }

    // --------------------------------------------------------------------------------------------
    // Inflation / donation attack non-profitability at offset 0 (force-feed via vm.deal)
    // --------------------------------------------------------------------------------------------

    function testFuzzInflationAttackNotProfitable(uint256 donation, uint256 victimDeposit) public {
        // Offset-0 vault (default), fresh from setUp.
        donation = bound(donation, 0, MAX_ETH);
        victimDeposit = bound(victimDeposit, 1, MAX_ETH);

        // 1. Attacker makes the canonical 1 wei first deposit.
        vm.deal(attacker, 1);
        vm.prank(attacker);
        vault.deposit{value: 1}(1, attacker);
        uint256 attackerShares = vault.balanceOf(attacker);

        // 2. Attacker force-feeds a donation directly into the vault balance (SELFDESTRUCT/coinbase analogue).
        vm.deal(address(vault), address(vault).balance + donation);
        uint256 attackerSpent = 1 + donation;

        // 3. Victim deposits.
        vm.deal(victim, victimDeposit);
        vm.prank(victim);
        vault.deposit{value: victimDeposit}(victimDeposit, victim);

        // 4. Attacker redeems everything they hold.
        uint256 attackerPayout = vault.previewRedeem(attackerShares);

        // Property: at offset 0 the attacker can never come out ahead of what they put in.
        assertLe(attackerPayout, attackerSpent, "inflation attack was profitable at offset 0");
    }

    // --------------------------------------------------------------------------------------------
    // Round-trips: a user never extracts more than they put in.
    // --------------------------------------------------------------------------------------------

    function testFuzzDepositRedeemRoundTrip(uint256 seed, uint256 assets) public {
        seed = bound(seed, 0, MAX_ETH);
        if (seed != 0) {
            vm.deal(address(this), seed);
            vault.deposit{value: seed}(seed, other);
        }

        assets = bound(assets, 0, MAX_ETH);
        vm.deal(victim, assets);
        vm.prank(victim);
        uint256 shares = vault.deposit{value: assets}(assets, victim);

        vm.prank(victim);
        uint256 redeemed = vault.redeem(shares, victim, victim);

        assertLe(redeemed, assets, "deposit->redeem extracted more than deposited");
    }

    function testFuzzMintRedeemRoundTrip(uint256 seed, uint256 shares) public {
        seed = bound(seed, 0, MAX_ETH);
        if (seed != 0) {
            vm.deal(address(this), seed);
            vault.deposit{value: seed}(seed, other);
        }

        shares = bound(shares, 0, 1e24);
        uint256 cost = vault.previewMint(shares);
        vm.assume(cost <= MAX_ETH);

        vm.deal(victim, cost);
        vm.prank(victim);
        vault.mint{value: cost}(shares, victim);

        vm.prank(victim);
        uint256 redeemed = vault.redeem(shares, victim, victim);

        assertLe(redeemed, cost, "mint->redeem extracted more than paid");
    }

    // --------------------------------------------------------------------------------------------
    // convertToShares ∘ convertToAssets is a contraction (rounding favors the vault).
    // --------------------------------------------------------------------------------------------

    function testFuzzConvertRoundTripContraction(uint256 seed, uint256 shares) public {
        seed = bound(seed, 0, MAX_ETH);
        if (seed != 0) {
            vm.deal(address(this), seed);
            vault.deposit{value: seed}(seed, other);
        }

        shares = bound(shares, 0, vault.totalSupply() == 0 ? MAX_ETH : vault.totalSupply());

        uint256 assets = vault.convertToAssets(shares);
        uint256 backToShares = vault.convertToShares(assets);

        assertLe(backToShares, shares, "convertToShares(convertToAssets(s)) > s: rounding favored user");
    }

    function testFuzzConvertAssetsRoundTripContraction(uint256 seed, uint256 assets) public {
        seed = bound(seed, 1, MAX_ETH);
        vm.deal(address(this), seed);
        vault.deposit{value: seed}(seed, other);

        assets = bound(assets, 0, MAX_ETH);

        uint256 shares = vault.convertToShares(assets);
        uint256 backToAssets = vault.convertToAssets(shares);

        assertLe(backToAssets, assets, "convertToAssets(convertToShares(a)) > a: rounding favored user");
    }

    // --------------------------------------------------------------------------------------------
    // Force-fed ETH does not break accounting (view functions still answer, withdraw still works).
    // --------------------------------------------------------------------------------------------

    function testFuzzForceFedEthDoesNotBreakAccounting(uint256 deposit, uint256 forceFed) public {
        deposit = bound(deposit, 1, MAX_ETH);
        forceFed = bound(forceFed, 0, MAX_ETH);

        vm.deal(victim, deposit);
        vm.prank(victim);
        uint256 shares = vault.deposit{value: deposit}(deposit, victim);

        // Force-feed extra ETH that mints no shares.
        vm.deal(address(vault), address(vault).balance + forceFed);

        assertEq(vault.totalAssets(), deposit + forceFed);
        // totalSupply unaffected by the donation.
        assertEq(vault.totalSupply(), shares);

        // Victim can still redeem; payout is well-defined and never reverts.
        uint256 expected = vault.previewRedeem(shares);
        vm.prank(victim);
        uint256 redeemed = vault.redeem(shares, victim, victim);
        assertEq(redeemed, expected);
    }

    // --------------------------------------------------------------------------------------------
    // Reentrancy (CEI-only, no guard): a malicious receiver that reenters withdraw/redeem during the
    // ETH `sendValue` push MAY or MAY NOT revert on its own, but MUST NOT (a) extract more native asset
    // than its shares entitle it to, or (b) drain other users' funds. Because `_withdraw` follows
    // checks-effects-interactions (allowance spent and shares burned BEFORE the ETH send), the reentrant
    // call observes an already-reduced state and any second extraction of the same shares is impossible.
    // --------------------------------------------------------------------------------------------

    function _fundReceiver(ReentrantReceiver r, uint256 deposit) internal returns (uint256 shares) {
        vm.deal(address(r), deposit);
        vm.prank(address(r));
        shares = vault.deposit{value: deposit}(deposit, address(r));
    }

    /// @dev Asserts the CEI invariants for a redeem whose payout reenters the vault.
    function _assertReentrancyCEI(ReentrantReceiver.Kind kind) internal {
        ReentrantReceiver r = new ReentrantReceiver();

        // Seed a second, honest depositor so the vault holds extra ETH the attacker could try to steal.
        uint256 otherDeposit = 10 ether;
        vm.deal(other, otherDeposit);
        vm.prank(other);
        uint256 otherShares = vault.deposit{value: otherDeposit}(otherDeposit, other);

        // Attacker becomes a share owner.
        uint256 attackerDeposit = 5 ether;
        uint256 attackerShares = _fundReceiver(r, attackerDeposit);

        // The attacker will try to re-redeem its FULL share balance again during the payout callback.
        r.setup(vault, kind, attackerShares);

        uint256 vaultBalBefore = address(vault).balance;
        uint256 totalSupplyBefore = vault.totalSupply();
        uint256 expectedPayout = vault.previewRedeem(attackerShares);

        vm.prank(address(r));
        vault.redeem(attackerShares, address(r), address(r));

        // The callback fired (control was handed to the attacker during the ETH send).
        assertTrue(r.reentered(), "callback never fired");

        // CEI: shares are burned BEFORE the ETH send, so the reentrant party observes zero balance for
        // itself and a totalSupply already reduced by exactly its shares.
        assertEq(r.observedSelfBalance(), 0, "attacker shares not burned before ETH send (CEI violated)");
        assertEq(
            r.observedTotalSupply(),
            totalSupplyBefore - attackerShares,
            "totalSupply not reduced before ETH send (CEI violated)"
        );

        // (a) No over-extraction: the attacker received exactly what its shares entitled it to, no more.
        //     The reentrant second redeem of the same (already-burned) shares cannot pay out anything extra.
        assertEq(
            address(r).balance,
            expectedPayout,
            "attacker extracted more native asset than its shares entitled it to"
        );

        // (b) No drain of other users: the vault retains at least the honest depositor's full entitlement,
        //     and lost exactly the attacker's payout and nothing more.
        assertEq(address(vault).balance, vaultBalBefore - expectedPayout, "vault over-drained");
        assertGe(
            address(vault).balance,
            vault.previewRedeem(otherShares),
            "vault cannot honor the honest depositor after the reentrant attempt (insolvent)"
        );

        // Solvency: only the honest depositor's shares remain.
        assertEq(vault.balanceOf(address(r)), 0, "attacker still holds shares");
        assertEq(vault.totalSupply(), otherShares, "share supply inconsistent after attack");

        // The honest depositor can still fully withdraw afterwards (funds not bricked).
        uint256 otherPayout = vault.previewRedeem(otherShares);
        vm.prank(other);
        uint256 redeemed = vault.redeem(otherShares, other, other);
        assertEq(redeemed, otherPayout, "honest depositor could not redeem after attack");
    }

    function testReentrancyWithdrawCannotOverDrain() public {
        _assertReentrancyCEI(ReentrantReceiver.Kind.Withdraw);
    }

    function testReentrancyRedeemCannotOverDrain() public {
        _assertReentrancyCEI(ReentrantReceiver.Kind.Redeem);
    }

    // --------------------------------------------------------------------------------------------
    // Allowance path: third-party redeem must spend share allowance and cannot move another's shares.
    // --------------------------------------------------------------------------------------------

    // --------------------------------------------------------------------------------------------
    // N8: Plain native-asset transfers to the vault (via `.call{value:}("")` / `transfer` / `send`)
    // hit the `receive()` and MUST revert with `ERC7535UnsolicitedDeposit`. Force-feeding via
    // `SELFDESTRUCT` / coinbase / `vm.deal` is the documented limitation: it bypasses the EVM
    // code path entirely and still works (totalAssets rises), which is what the inflation-attack
    // analysis already accounts for.
    // --------------------------------------------------------------------------------------------

    function testPlainEthTransferRevertsWithUnsolicitedDeposit() public {
        // Fund a caller and try a plain low-level transfer to the vault.
        address sender = makeAddr("plainSender");
        vm.deal(sender, 1 ether);

        uint256 totalAssetsBefore = vault.totalAssets();
        uint256 vaultBalBefore = address(vault).balance;

        vm.prank(sender);
        (bool ok, bytes memory ret) = address(vault).call{value: 1}("");

        // The receive() reverts with ERC7535UnsolicitedDeposit; the low-level call returns false
        // and the revert data carries the custom-error selector.
        assertFalse(ok, "plain ETH transfer to vault should fail");
        assertEq(
            bytes4(ret),
            ERC7535.ERC7535UnsolicitedDeposit.selector,
            "revert selector should be ERC7535UnsolicitedDeposit"
        );

        // The vault's balance and totalAssets are unchanged (no value entered).
        assertEq(address(vault).balance, vaultBalBefore, "vault balance changed despite revert");
        assertEq(vault.totalAssets(), totalAssetsBefore, "totalAssets changed despite revert");

        // Sender's wei is fully refunded by the revert (still has its full 1 ether).
        assertEq(sender.balance, 1 ether, "sender lost ETH despite revert");

        // Force-feeding via vm.deal (the SELFDESTRUCT / coinbase analogue) bypasses the EVM code
        // path entirely and still raises totalAssets — documented limitation of the `receive()` guard.
        uint256 forceFed = 7 ether;
        vm.deal(address(vault), vaultBalBefore + forceFed);
        assertEq(vault.totalAssets(), totalAssetsBefore + forceFed, "force-feed via vm.deal did not raise totalAssets");
    }

    function testThirdPartyRedeemRequiresAllowance() public {
        vm.deal(victim, 3 ether);
        vm.prank(victim);
        uint256 shares = vault.deposit{value: 3 ether}(3 ether, victim);

        // attacker has no allowance over victim's shares.
        vm.prank(attacker);
        vm.expectRevert();
        vault.redeem(shares, attacker, victim);

        // With allowance, it succeeds and burns exactly `shares` worth.
        vm.prank(victim);
        vault.approve(attacker, shares);
        vm.prank(attacker);
        vault.redeem(shares, attacker, victim);
        assertEq(vault.balanceOf(victim), 0);
    }
}
