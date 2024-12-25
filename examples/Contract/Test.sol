pragma solidity 0.4.26;

/**
 * @title SafeMath
 * @dev Math operations with safety checks
 */
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: division by zero");
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        uint256 c = a - b;
        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0, "SafeMath: modulo by zero");
        return a % b;
    }
}

/**
 * @title TestToken
 * @dev Simple ERC20 Token for testing
 */
contract TestToken {
    using SafeMath for uint256;

    string public name = "Test Token";
    string public symbol = "TEST";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 initialSupply) public {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
    }

    function transfer(address to, uint256 value) public returns (bool) {
        require(to != address(0));
        require(value <= balanceOf[msg.sender]);
        
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(value);
        balanceOf[to] = balanceOf[to].add(value);
        
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(to != address(0));
        require(value <= balanceOf[from]);
        require(value <= allowance[from][msg.sender]);

        balanceOf[from] = balanceOf[from].sub(value);
        balanceOf[to] = balanceOf[to].add(value);
        allowance[from][msg.sender] = allowance[from][msg.sender].sub(value);
        
        emit Transfer(from, to, value);
        return true;
    }
}

/**
 * @title FuzzableStaking
 * @dev Main contract optimized for fuzzing tests
 */
contract FuzzableStaking {
    using SafeMath for uint256;

    struct StakingConfig {
        uint256 minStakeAmount;
        uint256 maxStakeAmount;
        uint256 lockPeriod;
        uint256 rewardRate;
        bool active;
    }

    struct UserStake {
        uint256 amount;
        uint256 startTime;
        uint256 lockPeriod;
        uint256 lastRewardClaim;
        uint256 configId;
        bool active;
    }

    struct RewardConfig {
        uint256 baseRate;
        uint256 bonusRate;
        uint256 minLockPeriod;
        uint256 maxBonus;
    }

    // State variables
    TestToken public stakingToken;
    uint256 public totalStaked;
    uint256 public rewardPool;
    address public admin;
    bool public paused;
    uint256 public configCount;

    // Mappings
    mapping(uint256 => StakingConfig) public stakingConfigs;
    mapping(address => UserStake) public userStakes;
    mapping(address => uint256) public pendingRewards;
    mapping(uint256 => RewardConfig) public rewardConfigs;
    mapping(address => bool) public blacklisted;

    // Events for testing
    event Staked(address indexed user, uint256 amount, uint256 configId);
    event Unstaked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);
    event ConfigAdded(uint256 indexed configId);
    event ConfigUpdated(uint256 indexed configId);
    event EmergencyWithdrawn(address indexed user, uint256 amount);
    event BlacklistUpdated(address indexed user, bool status);

    // Modifiers
    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    modifier notBlacklisted() {
        require(!blacklisted[msg.sender], "Address blacklisted");
        _;
    }

    // Constructor
    constructor(address _tokenAddress) public {
        stakingToken = TestToken(_tokenAddress);
        admin = msg.sender;
        configCount = 0;
    }

    // Admin functions
    function addStakingConfig(
        uint256 _minStake,
        uint256 _maxStake,
        uint256 _lockPeriod,
        uint256 _rewardRate
    ) 
        external 
        onlyAdmin 
        returns (uint256)
    {
        require(_minStake > 0, "Invalid min stake");
        require(_maxStake >= _minStake, "Invalid max stake");
        require(_lockPeriod > 0, "Invalid lock period");
        require(_rewardRate > 0, "Invalid reward rate");

        uint256 configId = configCount;
        stakingConfigs[configId] = StakingConfig({
            minStakeAmount: _minStake,
            maxStakeAmount: _maxStake,
            lockPeriod: _lockPeriod,
            rewardRate: _rewardRate,
            active: true
        });

        configCount = configCount.add(1);
        emit ConfigAdded(configId);
        return configId;
    }

    function updateStakingConfig(
        uint256 _configId,
        uint256 _minStake,
        uint256 _maxStake,
        uint256 _lockPeriod,
        uint256 _rewardRate,
        bool _active
    ) 
        external 
        onlyAdmin 
    {
        require(_configId < configCount, "Invalid config ID");
        require(_minStake > 0, "Invalid min stake");
        require(_maxStake >= _minStake, "Invalid max stake");
        require(_lockPeriod > 0, "Invalid lock period");
        require(_rewardRate > 0, "Invalid reward rate");

        stakingConfigs[_configId] = StakingConfig({
            minStakeAmount: _minStake,
            maxStakeAmount: _maxStake,
            lockPeriod: _lockPeriod,
            rewardRate: _rewardRate,
            active: _active
        });

        emit ConfigUpdated(_configId);
    }

    function addRewardConfig(
        uint256 _configId,
        uint256 _baseRate,
        uint256 _bonusRate,
        uint256 _minLockPeriod,
        uint256 _maxBonus
    ) 
        external 
        onlyAdmin 
    {
        require(_configId < configCount, "Invalid config ID");
        
        rewardConfigs[_configId] = RewardConfig({
            baseRate: _baseRate,
            bonusRate: _bonusRate,
            minLockPeriod: _minLockPeriod,
            maxBonus: _maxBonus
        });
    }

    function updateBlacklist(address _user, bool _status) external onlyAdmin {
        blacklisted[_user] = _status;
        emit BlacklistUpdated(_user, _status);
    }

    function setPaused(bool _paused) external onlyAdmin {
        paused = _paused;
    }

    // Main functions
    function stake(uint256 _amount, uint256 _configId) external whenNotPaused notBlacklisted {
        require(_configId < configCount, "Invalid config ID");
        StakingConfig storage config = stakingConfigs[_configId];
        require(config.active, "Config not active");
        require(_amount >= config.minStakeAmount, "Below min stake");
        require(_amount <= config.maxStakeAmount, "Above max stake");
        require(!userStakes[msg.sender].active, "Already staking");

        require(stakingToken.transferFrom(msg.sender, address(this), _amount), "Transfer failed");

        userStakes[msg.sender] = UserStake({
            amount: _amount,
            startTime: block.timestamp,
            lockPeriod: config.lockPeriod,
            lastRewardClaim: block.timestamp,
            configId: _configId,
            active: true
        });

        totalStaked = totalStaked.add(_amount);
        emit Staked(msg.sender, _amount, _configId);
    }

    function calculateReward(address _user) public view returns (uint256) {
        UserStake storage stake = userStakes[_user];
        if (!stake.active) return 0;

        StakingConfig storage config = stakingConfigs[stake.configId];
        RewardConfig storage rewardConfig = rewardConfigs[stake.configId];

        uint256 timeStaked = block.timestamp.sub(stake.lastRewardClaim);
        uint256 baseReward = stake.amount.mul(config.rewardRate).mul(timeStaked).div(365 days).div(100);

        if (timeStaked >= rewardConfig.minLockPeriod) {
            uint256 bonus = baseReward.mul(rewardConfig.bonusRate).div(100);
            if (bonus > rewardConfig.maxBonus) {
                bonus = rewardConfig.maxBonus;
            }
            baseReward = baseReward.add(bonus);
        }

        return baseReward;
    }

    function claimReward() external whenNotPaused notBlacklisted {
        require(userStakes[msg.sender].active, "No active stake");
        
        uint256 reward = calculateReward(msg.sender);
        require(reward > 0, "No reward to claim");
        
        userStakes[msg.sender].lastRewardClaim = block.timestamp;
        require(stakingToken.transfer(msg.sender, reward), "Transfer failed");
        
        emit RewardClaimed(msg.sender, reward);
    }

    function unstake() external whenNotPaused notBlacklisted {
        UserStake storage stake = userStakes[msg.sender];
        require(stake.active, "No active stake");
        require(block.timestamp >= stake.startTime.add(stake.lockPeriod), "Lock period not ended");

        uint256 reward = calculateReward(msg.sender);
        uint256 totalAmount = stake.amount.add(reward);
        
        stake.active = false;
        totalStaked = totalStaked.sub(stake.amount);
        
        require(stakingToken.transfer(msg.sender, totalAmount), "Transfer failed");
        
        emit Unstaked(msg.sender, totalAmount);
    }

    function emergencyWithdraw() external notBlacklisted {
        UserStake storage stake = userStakes[msg.sender];
        require(stake.active, "No active stake");

        uint256 amount = stake.amount;
        stake.active = false;
        totalStaked = totalStaked.sub(amount);

        require(stakingToken.transfer(msg.sender, amount), "Transfer failed");
        emit EmergencyWithdrawn(msg.sender, amount);
    }

    // View functions for testing
    function getStakingConfig(uint256 _configId) 
        external 
        view 
        returns (
            uint256 minStake,
            uint256 maxStake,
            uint256 lockPeriod,
            uint256 rewardRate,
            bool active
        ) 
    {
        StakingConfig storage config = stakingConfigs[_configId];
        return (
            config.minStakeAmount,
            config.maxStakeAmount,
            config.lockPeriod,
            config.rewardRate,
            config.active
        );
    }

    function getUserStake(address _user)
        external
        view
        returns (
            uint256 amount,
            uint256 startTime,
            uint256 lockPeriod,
            uint256 lastRewardClaim,
            uint256 configId,
            bool active
        )
    {
        UserStake storage stake = userStakes[_user];
        return (
            stake.amount,
            stake.startTime,
            stake.lockPeriod,
            stake.lastRewardClaim,
            stake.configId,
            stake.active
        );k
    }
}