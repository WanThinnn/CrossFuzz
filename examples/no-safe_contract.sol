pragma solidity 0.4.26;

contract Sub {
    mapping(address => uint) public balances;

    function addBalances(address _addr, uint _amount) public {
        balances[_addr] += _amount;
    }

    function checkBalance(address _addr) public view returns (uint) {
        return balances[_addr];
    }
}

contract Child {
    uint inner;
}

contract E is Child {
    Sub sub;
    uint count;
    bool flag;
    address public owner;

    // Constructor
    function E(Sub _sub) public {
        sub = Sub(_sub);
        owner = msg.sender;  // Người tạo hợp đồng sẽ là chủ sở hữu
    }

    function setSub(Sub _sub) public {
        sub = Sub(_sub);
    }

    function setCount(uint _count) public {
        count = _count;
    }

    modifier minBalance {
        require(sub.checkBalance(msg.sender) >= 1 ether);
        _;
    }

    // Hàm này có thể bị tấn công do không có kiểm soát quyền truy cập
    function addBalance(address _addr, uint _amount) public {
        sub.addBalances(_addr, _amount);
        count += 1;
    }

    function getFlag() public view returns (bool) {
        return flag;
    }

    // Lỗi Access Control: bất kỳ ai cũng có thể gọi hàm này để thay đổi flag
    function setFlag(bool _flag) public {
        flag = _flag;
    }

    function getInner() public view returns (uint) {
        return inner;
    }

    function withdraw(address _addr, uint _amount) public minBalance {
        if (count > 50) {
            revert();
        } else {
            count += 2;
        }
        _addr.transfer(_amount);
    }
}
