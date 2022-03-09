// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "../utils/IStellaERC20.sol";

contract StellaDistributor is Ownable, ReentrancyGuard {
    // remember to change for mainnet deploy
    address constant _trustedForwarder =
        0x24eE59Fe03Cbc71e71bb05F6E66ffd49D6800363; //TRUSTED FORWARDER

    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    // Info of each user.
    struct UserInfo {
        uint256 amount; // How many LP tokens the user has provided.
        uint256 rewardDebt; // Reward debt. See explanation below.
        uint256 rewardLockedUp; // Reward locked up.
        uint256 nextHarvestUntil; // When can the user harvest again.
    }

    // Info of each pool.
    struct PoolInfo {
        IERC20 lpToken; // Address of LP token contract.
        uint256 allocPoint; // How many allocation points assigned to this pool. Stella to distribute per block.
        uint256 lastRewardBlock; // Last block number that Stella distribution occurs.
        uint256 accStellaPerShare; // Accumulated Stella per share, times 1e12. See below.
        uint16 depositFeeBP; // Deposit fee in basis points
        uint256 harvestInterval; // Harvest interval in seconds
        uint256 totalLp; // Total token in Pool
    }

    IStellaERC20 public stella;

    // The operator can only update EmissionRate and AllocPoint to protect tokenomics
    //i.e some wrong setting and a pools get too much allocation accidentally
    address private _operator;


    // Stella tokens created per block
    uint256 public stellaPerBlock;

    // Max harvest interval: 90 days
    uint256 public constant MAXIMUM_HARVEST_INTERVAL = 90 days;

    // Maximum deposit fee rate: 10%
    uint16 public constant MAXIMUM_DEPOSIT_FEE_RATE = 1000;

    // Info of each pool
    PoolInfo[] public poolInfo;

    // Info of each user that stakes LP tokens.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;

    // Total allocation points. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;

    // The block number when Stella mining starts.
    uint256 public startBlock;

    // Total locked up rewards
    uint256 public totalLockedUpRewards;

    // Total Stella in Stella Pools (can be multiple pools)
    uint256 public totalStellaInPools = 0;

    // Control support for EIP-2771 Meta Transactions
    bool public metaTxnsEnabled = false;

    // Team address.
    address public teamAddress;

    // Treasury address.
    address public treasuryAddress;

    // Investor address.
    address public investorAddress;

    // Percentage of pool rewards that goto the team.
    uint256 public teamPercent;

    // Percentage of pool rewards that goes to the treasury.
    uint256 public treasuryPercent;

    // Percentage of pool rewards that goes to the investor.
    uint256 public investorPercent;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(
        address indexed user,
        uint256 indexed pid,
        uint256 amount
    );
    event EmissionRateUpdated(
        address indexed caller,
        uint256 previousAmount,
        uint256 newAmount
    );
    event RewardLockedUp(
        address indexed user,
        uint256 indexed pid,
        uint256 amountLockedUp
    );
    event OperatorTransferred(
        address indexed previousOperator,
        address indexed newOperator
    );
    
    event AllocPointsUpdated(
        address indexed caller,
        uint256 previousAmount,
        uint256 newAmount
    );
    event MetaTxnsEnabled(address indexed caller);
    event MetaTxnsDisabled(address indexed caller);

    event SetTeamAddress(
        address indexed oldAddress,
        address indexed newAddress
    );

    event SetTreasuryAddress(
        address indexed oldAddress,
        address indexed newAddress
    );

    event SetInvestorAddress(
        address indexed oldAddress,
        address indexed newAddress
    );

    event SetTeamPercent(uint256 oldPercent, uint256 newPercent);

    event SetTreasuryPercent(uint256 oldPercent, uint256 newPercent);

    event SetInvestorPercent(uint256 oldPercent, uint256 newPercent);

    modifier onlyOperator() {
        require(
            _operator == msg.sender,
            "Operator: caller is not the operator"
        );
        _;
    }

    constructor(
        IStellaERC20 _stella,
        uint256 _stellaPerBlock,
        address _teamAddress,
        address _treasuryAddress,
        address _investorAddress,
        uint256 _teamPercent,
        uint256 _treasuryPercent,
        uint256 _investorPercent
        ) {

        require(
            0 <= _teamPercent && _teamPercent <= 100,
            "constructor: invalid team percent value"
        );
        require(
            0 <= _treasuryPercent && _treasuryPercent <= 100,
            "constructor: invalid treasury percent value"
        );
        require(
            0 <= _investorPercent && _investorPercent <= 100,
            "constructor: invalid investor percent value"
        );
        require(
            _teamPercent + _treasuryPercent + _investorPercent <= 100,
            "constructor: total percent over max"
        );

        //StartBlock always many years later from contract construct, will be set later in StartFarming function
        startBlock = block.number + (10 * 365 * 24 * 60 * 60);

        stella = _stella;
        stellaPerBlock = _stellaPerBlock;

        teamAddress = _teamAddress;
        treasuryAddress = _treasuryAddress;
        investorAddress = _investorAddress;

        teamPercent = _teamPercent;
        treasuryPercent = _treasuryPercent;
        investorPercent = _investorPercent;

        _operator = msg.sender;
        emit OperatorTransferred(address(0), _operator);
    }

    function isTrustedForwarder(address forwarder)
        public
        view
        virtual
        returns (bool)
    {
        return metaTxnsEnabled && forwarder == _trustedForwarder;
    }

    function _msgSender()
        internal
        view
        virtual
        override
        returns (address sender)
    {
        if (isTrustedForwarder(msg.sender)) {
            // The assembly code is more direct than the Solidity version using `abi.decode`.
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return super._msgSender();
        }
    }

    function _msgData()
        internal
        view
        virtual
        override
        returns (bytes calldata)
    {
        if (isTrustedForwarder(msg.sender)) {
            return msg.data[:msg.data.length - 20];
        } else {
            return super._msgData();
        }
    }

    function operator() public view returns (address) {
        return _operator;
    }

    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to)
        public
        pure
        returns (uint256)
    {
        return _to.sub(_from);
    }

    function transferOperator(address newOperator) public onlyOperator {
        require(
            newOperator != address(0),
            "TransferOperator: new operator is the zero address"
        );
        emit OperatorTransferred(_operator, newOperator);
        _operator = newOperator;
    }

    // Set farming start, can call only once
    function startFarming() public onlyOwner {
        require(block.number < startBlock, "Error::Farm started already");

        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            PoolInfo storage pool = poolInfo[pid];
            pool.lastRewardBlock = block.number;
        }

        startBlock = block.number;
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    // Add a new lp to the pool. Can only be called by the owner.
    // Can add multiple pool with same lp token without messing up rewards, because each pool's balance is tracked using its own totalLp
    function add(
        uint256 _allocPoint,
        IERC20 _lpToken,
        uint16 _depositFeeBP,
        uint256 _harvestInterval,
        bool _withUpdate
    ) public onlyOwner {
        require(
            _depositFeeBP <= MAXIMUM_DEPOSIT_FEE_RATE,
            "add: deposit fee too high"
        );
        require(
            _harvestInterval <= MAXIMUM_HARVEST_INTERVAL,
            "add: invalid harvest interval"
        );
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock = block.number > startBlock
            ? block.number
            : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolInfo.push(
            PoolInfo({
                lpToken: _lpToken,
                allocPoint: _allocPoint,
                lastRewardBlock: lastRewardBlock,
                accStellaPerShare: 0,
                depositFeeBP: _depositFeeBP,
                harvestInterval: _harvestInterval,
                totalLp: 0
            })
        );
    }

    // Update the given pool's Stella allocation point and deposit fee. Can only be called by the owner.
    function set(
        uint256 _pid,
        uint256 _allocPoint,
        uint16 _depositFeeBP,
        uint256 _harvestInterval,
        bool _withUpdate
    ) public onlyOwner {
        require(
            _depositFeeBP <= MAXIMUM_DEPOSIT_FEE_RATE,
            "set: deposit fee too high"
        );
        require(
            _harvestInterval <= MAXIMUM_HARVEST_INTERVAL,
            "set: invalid harvest interval"
        );
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(
            _allocPoint
        );
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
        poolInfo[_pid].harvestInterval = _harvestInterval;
    }

    // View function to see pending Stella on frontend.
    function pendingStella(uint256 _pid, address _user)
        external
        view
        returns (uint256)
    {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accStellaPerShare = pool.accStellaPerShare;
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));

        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier = getMultiplier(
                pool.lastRewardBlock,
                block.number
            );
            uint256 stellaReward = multiplier
                .mul(stellaPerBlock)
                .mul(pool.allocPoint)
                .div(totalAllocPoint);
            accStellaPerShare = accStellaPerShare.add(
                stellaReward.mul(1e12).div(lpSupply)
            );
        }

        uint256 pending = user.amount.mul(accStellaPerShare).div(1e12).sub(
            user.rewardDebt
        );
        return pending.add(user.rewardLockedUp);
    }

    // View function to see if user can harvest Stella.
    function canHarvest(uint256 _pid, address _user)
        public
        view
        returns (bool)
    {
        UserInfo storage user = userInfo[_pid][_user];
        return
            block.number >= startBlock &&
            block.timestamp >= user.nextHarvestUntil;
    }

    // Update reward vairables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }

        uint256 lpSupply = pool.totalLp;
        if (lpSupply == 0 || pool.allocPoint == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }

        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 stellaReward = multiplier
            .mul(stellaPerBlock)
            .mul(pool.allocPoint)
            .div(totalAllocPoint);

        uint256 lpPercent = 1000 -
        teamPercent -
        treasuryPercent -
        investorPercent;

        stella.mint(teamAddress, (stellaReward * teamPercent) / 1000);
        stella.mint(treasuryAddress, (stellaReward * treasuryPercent) / 1000);
        stella.mint(investorAddress, (stellaReward * investorPercent) / 1000);
        stella.mint(address(this), (stellaReward * lpPercent) / 1000);

        pool.accStellaPerShare =
            pool.accStellaPerShare +
            (((stellaReward * 1e12) / pool.totalLp) * lpPercent) /
            1000;
        
        pool.lastRewardBlock = block.number;
    }

    // Deposit LP tokens to MasterChef for Stella allocation.
    function deposit(uint256 _pid, uint256 _amount) public nonReentrant {
        require(
            block.number >= startBlock,
            "StellaDistributor: Can not deposit before start"
        );

        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];

        updatePool(_pid);

        payOrLockupPendingStella(_pid);

        if (_amount > 0) {
            uint256 beforeDeposit = pool.lpToken.balanceOf(address(this));
            pool.lpToken.safeTransferFrom(_msgSender(), address(this), _amount);
            uint256 afterDeposit = pool.lpToken.balanceOf(address(this));

            _amount = afterDeposit.sub(beforeDeposit);

            if (pool.depositFeeBP > 0) {
                uint256 depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                pool.lpToken.safeTransfer(treasuryAddress, depositFee);

                _amount = _amount.sub(depositFee);
            }

            user.amount = user.amount.add(_amount);
            pool.totalLp = pool.totalLp.add(_amount);

            if (address(pool.lpToken) == address(stella)) {
                totalStellaInPools = totalStellaInPools.add(_amount);
            }

        }
        user.rewardDebt = user.amount.mul(pool.accStellaPerShare).div(1e12);
        emit Deposit(_msgSender(), _pid, _amount);
    }

    // Withdraw tokens
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];

        //this will make sure that user can only withdraw from his pool
        require(user.amount >= _amount, "Withdraw: User amount not enough");

        //Cannot withdraw more than pool's balance
        require(pool.totalLp >= _amount, "Withdraw: Pool total not enough");


        updatePool(_pid);

        payOrLockupPendingStella(_pid);

        if (_amount > 0) {
            user.amount = user.amount.sub(_amount);
            pool.totalLp = pool.totalLp.sub(_amount);
            if (address(pool.lpToken) == address(stella)) {
                totalStellaInPools = totalStellaInPools.sub(_amount);
            }
            pool.lpToken.safeTransfer(_msgSender(), _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accStellaPerShare).div(1e12);
        emit Withdraw(_msgSender(), _pid, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];
        uint256 amount = user.amount;

        //Cannot withdraw more than pool's balance
        require(
            pool.totalLp >= amount,
            "EmergencyWithdraw: Pool total not enough"
        );

        user.amount = 0;
        user.rewardDebt = 0;
        user.rewardLockedUp = 0;
        user.nextHarvestUntil = 0;
        pool.totalLp = pool.totalLp.sub(amount);

        if (address(pool.lpToken) == address(stella)) {
            totalStellaInPools = totalStellaInPools.sub(amount);
        }
        pool.lpToken.safeTransfer(_msgSender(), amount);

        emit EmergencyWithdraw(_msgSender(), _pid, amount);
    }

    // Pay or lockup pending Stella.
    function payOrLockupPendingStella(uint256 _pid) internal {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];

        if (user.nextHarvestUntil == 0 && block.number >= startBlock) {
            user.nextHarvestUntil = block.timestamp.add(pool.harvestInterval);
        }

        uint256 pending = user.amount.mul(pool.accStellaPerShare).div(1e12).sub(
            user.rewardDebt
        );
        if (canHarvest(_pid, _msgSender())) {
            if (pending > 0 || user.rewardLockedUp > 0) {
                uint256 totalRewards = pending.add(user.rewardLockedUp);

                // reset lockup
                totalLockedUpRewards = totalLockedUpRewards.sub(
                    user.rewardLockedUp
                );
                user.rewardLockedUp = 0;
                user.nextHarvestUntil = block.timestamp.add(
                    pool.harvestInterval
                );

                // send rewards
                safeStellaTransfer(_msgSender(), totalRewards);
            }
        } else if (pending > 0) {
            user.rewardLockedUp = user.rewardLockedUp.add(pending);
            totalLockedUpRewards = totalLockedUpRewards.add(pending);
            emit RewardLockedUp(_msgSender(), _pid, pending);
        }
    }

    // Safe Stella transfer function, just in case if rounding error causes pool do not have enough Stella.
    function safeStellaTransfer(address _to, uint256 _amount) internal {
        if (stella.balanceOf(address(this)) > totalStellaInPools) {
            //StellaBal = total Stella in StellaDistributor - total Stella in Stella pools, this will make sure that StellaDistributor never transfer rewards from deposited Stella pools
            uint256 StellaBal = stella.balanceOf(address(this)).sub(
                totalStellaInPools
            );
            if (_amount >= StellaBal) {
                stella.transfer(_to, StellaBal);
            } else if (_amount > 0) {
                stella.transfer(_to, _amount);
            }
        }
    }


    // Pancake has to add hidden dummy pools in order to alter the emission, here we make it simple and transparent to all.
    function updateEmissionRate(uint256 _stellaPerBlock) public onlyOperator {
        massUpdatePools();

        emit EmissionRateUpdated(msg.sender, stellaPerBlock, _stellaPerBlock);
        stellaPerBlock = _stellaPerBlock;
    }

    function updateAllocPoint(
        uint256 _pid,
        uint256 _allocPoint,
        bool _withUpdate
    ) public onlyOperator {
        if (_withUpdate) {
            massUpdatePools();
        }

        emit AllocPointsUpdated(
            _msgSender(),
            poolInfo[_pid].allocPoint,
            _allocPoint
        );

        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(
            _allocPoint
        );
        poolInfo[_pid].allocPoint = _allocPoint;
    }

    // Enable support for meta transactions
    function enableMetaTxns() public onlyOperator {
        require(!metaTxnsEnabled, "Meta transactions are already enabled");

        metaTxnsEnabled = true;
        emit MetaTxnsEnabled(_msgSender());
    }

    // Disable support for meta transactions
    function disableMetaTxns() public onlyOperator {
        require(metaTxnsEnabled, "Meta transactions are already disabled");

        metaTxnsEnabled = false;
        emit MetaTxnsDisabled(_msgSender());
    }

    // Function to harvest many pools in a single transaction
    function harvestMany(uint256[] calldata _pids) public {
        for (uint256 index = 0; index < _pids.length; ++index) {
            deposit(_pids[index], 0);
        }
    }

    // Update team address by the previous team address.
    function setTeamAddress(address _teamAddress) public {
        require(
            msg.sender == teamAddress,
            "set team address: only previous team address can call this method"
        );
        teamAddress = _teamAddress;
        emit SetTeamAddress(msg.sender, _teamAddress);
    }

    function setTeamPercent(uint256 _newTeamPercent) public onlyOwner {
        require(
            0 <= _newTeamPercent && _newTeamPercent <= 100,
            "set team percent: invalid percent value"
        );
        require(
            treasuryPercent + _newTeamPercent + investorPercent <= 100,
            "set team percent: total percent over max"
        );
        emit SetTeamPercent(teamPercent, _newTeamPercent);
        teamPercent = _newTeamPercent;
    }

    // Update treasury address by the previous treasury.
    function setTreasuryAddr(address _treasuryAddress) public {
        require(msg.sender == treasuryAddress, "set treasury address: wut?");
        treasuryAddress = _treasuryAddress;
        emit SetTreasuryAddress(msg.sender, _treasuryAddress);
    }

    function setTreasuryPercent(uint256 _newTreasuryPercent) public onlyOwner {
        require(
            0 <= _newTreasuryPercent && _newTreasuryPercent <= 100,
            "set treasury percent: invalid percent value"
        );
        require(
            teamPercent + _newTreasuryPercent + investorPercent <= 100,
            "set treasury percent: total percent over max"
        );
        emit SetTeamPercent(treasuryPercent, _newTreasuryPercent);
        treasuryPercent = _newTreasuryPercent;
    }

    // Update the investor address by the previous investor.
    function setInvestorAddress(address _investorAddress) public {
        require(
            msg.sender == investorAddress,
            "set investor address: only previous investor can call this method"
        );
        investorAddress = _investorAddress;
        emit SetInvestorAddress(msg.sender, _investorAddress);
    }

    function setInvestorPercent(uint256 _newInvestorPercent) public onlyOwner {
        require(
            0 <= _newInvestorPercent && _newInvestorPercent <= 100,
            "set investor percent: invalid percent value"
        );
        require(
            teamPercent + _newInvestorPercent + treasuryPercent <= 100,
            "set investor percent: total percent over max"
        );
        emit SetTeamPercent(investorPercent, _newInvestorPercent);
        investorPercent = _newInvestorPercent;
    }
}