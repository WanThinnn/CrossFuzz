pragma solidity 0.4.26;

contract LendingPool {
    mapping(address => uint) public balances;

    constructor() public {
        balances[msg.sender] = 1000 ether;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function flashLoan(address receiver, uint amount) public {
        require(amount <= balances[address(this)], "Not enough liquidity in pool");
        uint previousBalance = balances[address(this)];
        FlashLoanReceiver(receiver).executeOperation.value(amount)(amount);
        require(balances[address(this)] == previousBalance, "Balance mismatch after loan");
    }

    function reward(address user, uint rewardAmount) public {
        balances[user] += rewardAmount; // Potential overflow
    }
}

contract FlashLoanReceiver {
    LendingPool public pool;

    constructor(address _pool) public {
        pool = LendingPool(_pool);
    }

    function executeFlashLoan(uint amount) public {
        pool.flashLoan(address(this), amount);
    }

    function executeOperation(uint amount) public payable {
        require(msg.value == amount, "Incorrect loan amount received");
        pool.reward(msg.sender, 2**256 - 1); // Intentional overflow
        address(pool).transfer(amount);
    }
}
