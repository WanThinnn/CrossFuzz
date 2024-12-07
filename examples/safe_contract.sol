// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Sub Contract
contract Sub {
    mapping(address => uint256) private balances;
    address private immutable owner;

    event BalanceAdded(address indexed user, uint256 amount);
    event BalanceSubtracted(address indexed user, uint256 amount);

    error NotOwner();
    error ZeroAddress();
    error InsufficientBalance();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addBalances(address _addr, uint256 _amount) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddress();
        balances[_addr] += _amount;
        emit BalanceAdded(_addr, _amount);
    }

    function subtractBalances(address _addr, uint256 _amount) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddress();
        if (balances[_addr] < _amount) revert InsufficientBalance();
        balances[_addr] -= _amount;
        emit BalanceSubtracted(_addr, _amount);
    }

    function checkBalance(address _addr) external view returns (uint256) {
        return balances[_addr];
    }
}

contract Child {
    uint256 private inner;

    function getInner() public view returns (uint256) {
        return inner;
    }

    function setInner(uint256 _value) internal {
        inner = _value;
    }
}

contract E is Child {
    Sub public immutable sub;
    uint256 private count;
    bool private flag;
    address private immutable owner;

    uint256 private constant MAX_WITHDRAW = 10 ether;
    uint256 private constant MIN_BALANCE = 1 ether;
    uint256 private _status;

    event Withdrawal(address indexed user, uint256 amount);
    event BalanceUpdated(address indexed user, uint256 newBalance);
    event CountUpdated(uint256 newCount);
    event FlagUpdated(bool newFlag);

    error NotOwner();
    error ReentrancyGuard();
    error ZeroAddress(); 
    error InvalidAmount();
    error InsufficientBalance();
    error CountExceeded();
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (_status != 0) revert ReentrancyGuard();
        _status = 1;
        _;
        _status = 0;
    }

    constructor(Sub _sub) {
        if (address(_sub) == address(0)) revert ZeroAddress();
        sub = _sub;
        owner = msg.sender;
    }

    function setCount(uint256 _count) external onlyOwner {
        count = _count;
        emit CountUpdated(_count);
    }

    function addBalance(address _addr, uint256 _amount) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddress();
        if (_amount == 0) revert InvalidAmount();
        sub.addBalances(_addr, _amount);
        count += 1;
        emit CountUpdated(count);
    }

    function getFlag() external view returns (bool) {
        return flag;
    }

    function setFlag(bool _flag) external onlyOwner {
        flag = _flag;
        emit FlagUpdated(_flag);
    }

    function withdraw(address payable _addr, uint256 _amount) external nonReentrant {
        if (_addr == address(0)) revert ZeroAddress();
        if (_amount == 0 || _amount > MAX_WITHDRAW) revert InvalidAmount();
        if (sub.checkBalance(msg.sender) < MIN_BALANCE) revert InsufficientBalance();
        if (sub.checkBalance(msg.sender) < _amount) revert InsufficientBalance();

        sub.subtractBalances(msg.sender, _amount);

        if (count > 50) revert CountExceeded();
        count += 2;
        emit CountUpdated(count);

        (bool sent,) = _addr.call{value: _amount}("");
        if (!sent) revert TransferFailed();

        emit Withdrawal(msg.sender, _amount);
        emit BalanceUpdated(msg.sender, sub.checkBalance(msg.sender));
    }

    receive() external payable {
        emit BalanceUpdated(msg.sender, address(this).balance);
    }
}