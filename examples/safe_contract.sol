pragma solidity 0.4.26;

/**
 * @title SafeMath Library
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        uint256 c = a - b;
        return c;
    }
}

contract Sub {
    using SafeMath for uint256;
    mapping(address => uint256) private balances;

    /**
     * @dev Add balance for a specific address
     * @param _addr Address to add balance to
     * @param _amount Amount to add
     */
    function addBalances(address _addr, uint256 _amount) public {
        require(_addr != address(0), "Invalid address");
        balances[_addr] = balances[_addr].add(_amount);
    }

    /**
     * @dev Check balance of a specific address
     * @param _addr Address to check balance for
     * @return Balance of the address
     */
    function checkBalance(address _addr) public view returns (uint256) {
        return balances[_addr];
    }
}

contract Child {
    uint256 private inner;
}

contract E is Child {
    Sub private sub;
    uint256 private count;
    bool private flag;

    /**
     * @dev Constructor to set the Sub contract
     * @param _sub Address of the Sub contract
     */
    function E(Sub _sub) public {
        require(address(_sub) != address(0), "Invalid Sub contract address");
        sub = _sub;
    }

    /**
     * @dev Set a new Sub contract
     * @param _sub Address of the new Sub contract
     */
    function setSub(Sub _sub) public {
        require(address(_sub) != address(0), "Invalid Sub contract address");
        sub = _sub;
    }
}
