// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.7.0) (token/ERC20/extensions/ERC7535.sol)

pragma solidity ^0.8.24;

import {IERC20, IERC20Metadata, ERC20} from "../ERC20.sol";
import {IERC7535} from "../../../interfaces/IERC7535.sol";
import {Address} from "../../../utils/Address.sol";
import {Math} from "../../../utils/math/Math.sol";

/**
 * @dev Implementation of the ERC-7535 "Native Asset ERC-4626 Tokenized Vault" as defined in
 * https://eips.ethereum.org/EIPS/eip-7535[ERC-7535].
 *
 * ERC-7535 is an adaptation of ERC-4626 that uses Ether (or the chain's native EVM asset) as the underlying
 * asset instead of an ERC-20 token. The {asset} placeholder is the ERC-7528 native-asset address
 * `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`, {totalAssets} is the contract's own Ether balance, and the
 * native asset enters the Vault as `msg.value` on the `payable` {deposit} and {mint} functions rather than
 * through an ERC-20 `transferFrom`.
 *
 * This extension allows the minting and burning of "shares" (represented using the ERC-20 inheritance) in exchange for
 * the native asset through standardized {deposit}, {mint}, {redeem} and {burn} workflows. This contract extends the
 * ERC-20 standard. Any additional extensions included along it would affect the "shares" token represented by this
 * contract and not the native "asset".
 *
 * NOTE: This contract does not inherit `ERC4626`. ERC-7535 requires {deposit} and {mint} to have a `payable`
 * state mutability, which is incompatible with the `nonpayable` definitions in ERC-4626 (Solidity does not
 * allow a `payable` function to override a `nonpayable` one). The structure, rounding directions, internal
 * seams (`_deposit`/`_withdraw`/`_convertToShares`/`_convertToAssets`) and the virtual-offset anti-inflation
 * math mirror `contracts/token/ERC20/extensions/ERC4626.sol`.
 *
 * IMPORTANT: A vault backed by a wrapped native asset (such as WETH9) MUST NOT use this contract; per
 * ERC-7528 and ERC-7535 such a vault is a plain ERC-4626 over the wrapper ERC-20 and MUST report that
 * wrapper's address from {asset}, not the native-asset placeholder.
 *
 * [CAUTION]
 * ====
 * In empty (or nearly empty) ERC-7535 vaults, deposits are at high risk of being stolen through frontrunning
 * with a "donation" to the vault that inflates the price of a share. This is variously known as a donation or inflation
 * attack and is essentially a problem of slippage. Vault deployers can protect against this attack by making an initial
 * deposit of a non-trivial amount of the asset, such that price manipulation becomes infeasible. Withdrawals may
 * similarly be affected by slippage. Users can protect against this attack as well as unexpected slippage in general by
 * verifying the amount received is as expected, using a wrapper that performs these checks.
 *
 * Since {totalAssets} reads `address(this).balance`, the native asset can additionally be force-fed into the Vault
 * (e.g. through `SELFDESTRUCT` or block-reward payments) without minting shares, bypassing any `receive`/`fallback`
 * restriction. As in `ERC4626`, this implementation introduces configurable virtual assets and shares to help
 * developers mitigate that risk. The `_decimalsOffset()` corresponds to an offset in the decimal representation
 * between the underlying asset's decimals and the vault decimals. This offset also determines the rate of virtual
 * shares to virtual assets in the vault, which itself determines the initial exchange rate. While not fully preventing
 * the attack, analysis shows that the default offset (0) makes it non-profitable even if an attacker is able to capture
 * value from multiple user deposits, as a result of the value being captured by the virtual shares (out of the
 * attacker's donation) matching the attacker's expected gains. With a larger offset, the attack becomes orders of
 * magnitude more expensive than it is profitable. More details about the underlying math can be found
 * xref:ROOT:erc4626.adoc#inflation-attack[here].
 *
 * The drawback of this approach is that the virtual shares do capture (a very small) part of the value being accrued
 * to the vault. Also, if the vault experiences losses, the users try to exit the vault, the virtual shares and assets
 * will cause the first user to exit to experience reduced losses in detriment to the last users that will experience
 * bigger losses. Developers willing to revert back to the pre-virtual-offset behavior just need to override the
 * `_convertToShares` and `_convertToAssets` functions.
 * ====
 *
 * [NOTE]
 * ====
 * When overriding this contract, some elements must be considered:
 *
 * * When overriding the behavior of the deposit or withdraw mechanisms, it is recommended to override the internal
 * functions. Overriding {_deposit} automatically affects both {deposit} and {mint}. Similarly, overriding {_withdraw}
 * automatically affects both {withdraw} and {redeem}. Overall it is not recommended to override the public facing
 * functions since that could lead to inconsistent behaviors between the {deposit} and {mint} or between {withdraw} and
 * {redeem}, which is documented to have led to loss of funds.
 *
 * * Overrides to the deposit or withdraw mechanism must be reflected in the preview functions as well.
 *
 * * {maxWithdraw} depends on {maxRedeem}. Therefore, overriding {maxRedeem} only is enough. On the other hand,
 * overriding {maxWithdraw} only would have no effect on {maxRedeem}, and could create an inconsistency between the two
 * functions.
 *
 * * If {previewRedeem} is overridden to revert, {maxWithdraw} must be overridden as necessary to ensure it
 * always return successfully.
 *
 * * On entry to the `payable` {deposit} and {mint}, the incoming `msg.value` has already been credited to
 * `address(this).balance`, and therefore to {totalAssets}. To avoid counting the depositor's own Ether as
 * pre-existing assets (which would misprice the issued shares), all share math goes through {_convertToShares} /
 * {_convertToAssets}, which read the pre-call total from {_pretotalAssets}. In any non-`payable` context
 * `msg.value` is `0` and {_pretotalAssets} equals {totalAssets}, so the same conversion call yields the live
 * balance for public previews and the pre-call balance for the payable entrypoints. Off-chain previews must
 * still be performed *before* sending value, since the public `view` functions cannot account for an in-flight
 * `msg.value`.
 *
 * * {deposit} requires `msg.value == assets` and {mint} requires `msg.value == previewMint(shares)` exactly;
 * there is no refund path. ERC-7535 says `deposit` MAY ignore the `assets` argument, but ignoring it lets a
 * buggy integrator silently desync the amount they meant to send from the amount they actually paid, with no
 * way to detect it on-chain. Requiring strict equality surfaces the desync immediately as a typed revert
 * ({ERC7535UnexpectedDepositValue} / {ERC7535UnexpectedMintValue}) and keeps the emitted `Deposit` event
 * provably consistent with the wei that entered the Vault; the cost is one comparison and the loss of the
 * spec-permitted "MAY ignore" permissiveness, which the named error makes a safer trade.
 *
 * * The native asset is sent out on {withdraw}/{redeem} via {Address-sendValue}, which forwards all remaining
 * gas (so contract receivers like multisigs and AA wallets work, unlike the spec's suggested 2300-gas stipend).
 * The send is the last step of the checks-effects-interactions flow in {_withdraw} (allowance spent and shares
 * burned first), so a reentrant call from the receiver observes a consistent, already-reduced state. As in
 * `ERC4626`, reentrancy safety relies on this ordering rather than on a reentrancy guard. This contract
 * implements a {receive} function that reverts with {ERC7535UnsolicitedDeposit}, so plain transfers to it
 * fail loudly with a named reason. Note that the native asset can still be force-fed into the Vault
 * (e.g. through `SELFDESTRUCT` or block-reward payments) without minting shares, bypassing this guard.
 *
 * * Overrides of {_pretotalAssets} MUST return a value less than or equal to {totalAssets} in every context.
 * Overstating it inflates the share price during {deposit}/{mint}; understating it during a `view` call
 * misprices the public previews. Overrides of {_convertToShares}/{_convertToAssets} MUST go through
 * {_pretotalAssets} (do not read {totalAssets} or `msg.value` directly), otherwise the in-flight `msg.value`
 * is re-mixed into the rate and the rounding/skew bugs this seam is designed to prevent come back.
 *
 * * Overrides of {totalAssets} MUST NOT revert (ERC-4626 / ERC-7535 require it to return a value). When sourcing
 * the total from an external oracle, wrap the call in `try/catch` and return a safe fallback. Overstating
 * {totalAssets} will make {withdraw}/{redeem} attempt to send more than `address(this).balance` and revert
 * in `Address.sendValue`, locking exits until the balance catches up with the reported total.
 *
 * * Overrides of {_deposit} MUST NOT introduce an outbound native-asset call (e.g. a refund of "excess"
 * `msg.value`) before `_mint`: that reopens the reentrancy / refund-griefing class this design avoids by
 * requiring an exact `msg.value`. Overrides of {_withdraw} MUST preserve the checks-effects-interactions
 * ordering (allowance spent and shares burned BEFORE the outbound transfer).
 *
 * * Overrides of {_decimalsOffset} must keep the offset such that `18 + offset` fits in a `uint8` (i.e.
 * `offset <= 237`); larger values overflow {decimals}.
 *
 * * When overriding {maxDeposit} / {maxMint}, keep them consistent with any override of {previewDeposit} /
 * {previewMint}. The standard requires {previewDeposit} to act as though the deposit were accepted; a max that
 * disagrees with the preview produces misleading UI quotes. This is symmetric to the {maxWithdraw} / {maxRedeem}
 * consistency noted above.
 * ====
 */
abstract contract ERC7535 is ERC20, IERC7535 {
    using Math for uint256;

    /// @dev The ERC-7528 placeholder address representing the native asset; exposed through {asset}.
    address private constant NATIVE_ASSET = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /**
     * @dev Attempted to deposit more assets than the max amount for `receiver`.
     */
    error ERC7535ExceededMaxDeposit(address receiver, uint256 assets, uint256 max);

    /**
     * @dev Attempted to mint more shares than the max amount for `receiver`.
     */
    error ERC7535ExceededMaxMint(address receiver, uint256 shares, uint256 max);

    /**
     * @dev Attempted to withdraw more assets than the max amount for `owner`.
     */
    error ERC7535ExceededMaxWithdraw(address owner, uint256 assets, uint256 max);

    /**
     * @dev Attempted to redeem more shares than the max amount for `owner`.
     */
    error ERC7535ExceededMaxRedeem(address owner, uint256 shares, uint256 max);

    /**
     * @dev Attempted to {deposit} with a `msg.value` that does not match the `assets` argument.
     */
    error ERC7535UnexpectedDepositValue(uint256 value, uint256 assets);

    /**
     * @dev Attempted to {mint} with a `msg.value` that does not match the cost of the requested `shares`.
     */
    error ERC7535UnexpectedMintValue(uint256 value, uint256 cost);

    /**
     * @dev Reverts on a plain native-asset transfer to the vault — value enters only via {deposit} or {mint}.
     */
    error ERC7535UnsolicitedDeposit();

    /**
     * @dev Decimals are computed by adding the decimal offset on top of the native asset's decimals, which are fixed
     * at 18 (the native asset has no `decimals()` to query).
     *
     * See {IERC20Metadata-decimals}.
     */
    function decimals() public view virtual override(IERC20Metadata, ERC20) returns (uint8) {
        return 18 + _decimalsOffset();
    }

    /// @inheritdoc IERC7535
    function asset() public view virtual returns (address) {
        return NATIVE_ASSET;
    }

    /// @inheritdoc IERC7535
    function totalAssets() public view virtual returns (uint256) {
        return address(this).balance;
    }

    /// @inheritdoc IERC7535
    function convertToShares(uint256 assets) public view virtual returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    /// @inheritdoc IERC7535
    function convertToAssets(uint256 shares) public view virtual returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    /// @inheritdoc IERC7535
    function maxDeposit(address) public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /// @inheritdoc IERC7535
    function maxMint(address) public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /// @inheritdoc IERC7535
    function maxWithdraw(address owner) public view virtual returns (uint256) {
        return previewRedeem(maxRedeem(owner));
    }

    /// @inheritdoc IERC7535
    function maxRedeem(address owner) public view virtual returns (uint256) {
        return balanceOf(owner);
    }

    /// @inheritdoc IERC7535
    function previewDeposit(uint256 assets) public view virtual returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    /// @inheritdoc IERC7535
    function previewMint(uint256 shares) public view virtual returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Ceil);
    }

    /// @inheritdoc IERC7535
    function previewWithdraw(uint256 assets) public view virtual returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Ceil);
    }

    /// @inheritdoc IERC7535
    function previewRedeem(uint256 shares) public view virtual returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    /// @inheritdoc IERC7535
    function deposit(uint256 assets, address receiver) public payable virtual returns (uint256) {
        if (msg.value != assets) {
            revert ERC7535UnexpectedDepositValue(msg.value, assets);
        }

        uint256 maxAssets = maxDeposit(receiver);
        if (assets > maxAssets) {
            revert ERC7535ExceededMaxDeposit(receiver, assets, maxAssets);
        }

        // `msg.value` is already part of `totalAssets()` on entry; `_convertToShares` reads {_pretotalAssets}
        // so the share price is computed against the pre-call balance.
        uint256 shares = _convertToShares(assets, Math.Rounding.Floor);
        _deposit(_msgSender(), receiver, assets, shares);

        return shares;
    }

    /// @inheritdoc IERC7535
    function mint(uint256 shares, address receiver) public payable virtual returns (uint256) {
        uint256 maxShares = maxMint(receiver);
        if (shares > maxShares) {
            revert ERC7535ExceededMaxMint(receiver, shares, maxShares);
        }

        // `msg.value` is already part of `totalAssets()` on entry; `_convertToAssets` reads {_pretotalAssets}
        // so the cost is computed against the pre-call balance.
        uint256 assets = _convertToAssets(shares, Math.Rounding.Ceil);
        if (msg.value != assets) {
            revert ERC7535UnexpectedMintValue(msg.value, assets);
        }

        _deposit(_msgSender(), receiver, assets, shares);

        return assets;
    }

    /// @inheritdoc IERC7535
    function withdraw(uint256 assets, address receiver, address owner) public virtual returns (uint256) {
        uint256 maxAssets = maxWithdraw(owner);
        if (assets > maxAssets) {
            revert ERC7535ExceededMaxWithdraw(owner, assets, maxAssets);
        }

        uint256 shares = previewWithdraw(assets);
        _withdraw(_msgSender(), receiver, owner, assets, shares);

        return shares;
    }

    /// @inheritdoc IERC7535
    function redeem(uint256 shares, address receiver, address owner) public virtual returns (uint256) {
        uint256 maxShares = maxRedeem(owner);
        if (shares > maxShares) {
            revert ERC7535ExceededMaxRedeem(owner, shares, maxShares);
        }

        uint256 assets = previewRedeem(shares);
        _withdraw(_msgSender(), receiver, owner, assets, shares);

        return assets;
    }

    /**
     * @dev Internal conversion function (from assets to shares) with support for rounding direction.
     */
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
        return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), _pretotalAssets() + 1, rounding);
    }

    /**
     * @dev Internal conversion function (from shares to assets) with support for rounding direction.
     */
    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view virtual returns (uint256) {
        return shares.mulDiv(_pretotalAssets() + 1, totalSupply() + 10 ** _decimalsOffset(), rounding);
    }

    /**
     * @dev Returns the value of {totalAssets} that the share math should price *against* — i.e. the contract's
     * balance excluding any in-flight `msg.value` from the current `payable` call. In a non-`payable` context
     * (every `view` call, and {withdraw}/{redeem}) `msg.value` is `0` and the result equals {totalAssets}; in
     * the `payable` {deposit}/{mint} entrypoints the subtraction yields the pre-call balance, which is what
     * {ERC4626}-style share math computes against. `msg.value` is not readable from a `view` function, hence
     * this internal seam rather than folding the adjustment into {totalAssets} itself.
     */
    function _pretotalAssets() internal view virtual returns (uint256) {
        return totalAssets() - msg.value;
    }

    /**
     * @dev Deposit/mint common workflow.
     *
     * The native asset has already been received with the call as `msg.value`, so there is no inbound transfer to
     * perform; we only mint the shares and emit the event.
     */
    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal virtual {
        _mint(receiver, shares);

        emit Deposit(caller, receiver, assets, shares);
    }

    /**
     * @dev Withdraw/redeem common workflow.
     */
    function _withdraw(
        address caller,
        address receiver,
        address owner,
        uint256 assets,
        uint256 shares
    ) internal virtual {
        if (caller != owner) {
            _spendAllowance(owner, caller, shares);
        }

        // Follow checks-effects-interactions: spend allowance and burn the shares before sending the native asset out,
        // so that any reentrancy from the recipient observes a consistent, reduced-share state.
        _burn(owner, shares);
        _transferOut(receiver, assets);

        emit Withdraw(caller, receiver, owner, assets, shares);
    }

    /// @dev Performs a transfer out of the native asset. The default implementation uses `Address.sendValue`.
    /// Used by {_withdraw}.
    function _transferOut(address to, uint256 assets) internal virtual {
        Address.sendValue(payable(to), assets);
    }

    function _decimalsOffset() internal view virtual returns (uint8) {
        return 0;
    }

    /// @dev Reverts on plain native-asset transfers; value must enter via {deposit} or {mint}.
    receive() external payable {
        revert ERC7535UnsolicitedDeposit();
    }
}
