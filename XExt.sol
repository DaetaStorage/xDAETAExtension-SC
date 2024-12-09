// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

contract XEXT is EIP712 {
    string private constant SIGNING_DOMAIN = "xExtension";
    string private constant SIGNATURE_VERSION = "1";
    IERC20 public token;
    address public owner;

    uint256 public totalClaimedPoints;
    uint256 public tokenPerPoint = 1;
    uint256 public multiplier = 100;
    uint256 public priceMultiplier = 10 ** 6;
    uint256 public decimals = 10 ** 18;

    mapping(address => uint256) public userClaimed;
    mapping(address => uint256) public userLastClaimedAt;

    struct ExtensionClientData {
        address client;
        uint256 points;
        address server;
        bytes signature;
    }

    constructor(address _token) EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can execute this");
        _;
    }

    function updateTokenPerPoint(uint256 rate) public onlyOwner {
        tokenPerPoint = rate;
    }

    function transferOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }

    function claimRewards(ExtensionClientData calldata voucher, uint256 price) public {
        require(_verify(voucher) == owner, "You are not allowed to claim rewards");

        require(voucher.points > 0, "Number of points must be greater than 0");
        require(
            block.timestamp >= userLastClaimedAt[msg.sender] + 7 days,
            "You can claim your rewards only one time a week"
        );

        uint256 tokenAmount = (voucher.points * tokenPerPoint * decimals * priceMultiplier) / multiplier / price;
        require(token.balanceOf(address(this)) >= tokenAmount, "Reward token is not enough");

        // Transfer the tokens and check for success
        require(token.transfer(msg.sender, tokenAmount), "Token transfer failed");

        userClaimed[msg.sender] += tokenAmount;
        totalClaimedPoints += tokenAmount;
        userLastClaimedAt[msg.sender] = block.timestamp;
    }

    function _hash(ExtensionClientData calldata voucher) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256("ExtensionClientData(address client,uint256 points,address server)"),
                        msg.sender,
                        voucher.points,
                        address(this)
                    )
                )
            );
    }

    function _verify(ExtensionClientData calldata voucher) internal view returns (address) {
        bytes32 digest = _hash(voucher);
        return ECDSA.recover(digest, voucher.signature);
    }
}
