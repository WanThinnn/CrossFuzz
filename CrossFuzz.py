import json
import shutil
import sys
import os

import config
from comp import analysis_depend_contract, analysis_main_contract_constructor

'''
Chương trình bắt đầu bằng việc gọi hàm run() để thực hiện fuzzing trên hợp đồng thông minh với các tham số cấu hình cụ thể.
Kết quả từ quá trình fuzzing được sao chép đến vị trí lưu trữ để phân tích sau này.
Nếu tệp được chạy trực tiếp, nó sẽ thiết lập môi trường cần thiết bằng cách xác định đường dẫn Python và fuzzer.
Hàm test_run() được gọi hai lần để thực hiện các phiên kiểm thử, có thể với mục đích khác nhau hoặc để xác nhận tính ổn định.
Dòng gọi hàm cli() bị chú thích có thể cho thấy người phát triển đang thử nghiệm và chưa muốn sử dụng giao diện dòng lệnh tại thời điểm này.

'''



def run(_file_path: str, _main_contract, solc_version: str, evm_version: str, timeout: int, _depend_contracts: list,
        max_individual_length: int, _constructor_args: list, _solc_path: str, _duplication: str = '0'):
    '''
    Gọi hàm run và lưu kết quả vào biến res:
    1. Mục đích: Chạy quá trình fuzzing trên hợp đồng thông minh bằng cách gọi hàm run với các tham số cần thiết.
    2. Các tham số:
        p: Đường dẫn tới tệp hợp đồng thông minh.
        c_name: Tên của hợp đồng chính cần fuzzing.
        solc_version: Phiên bản của trình biên dịch Solidity.
        "byzantium": Phiên bản EVM được sử dụng.
        fuzz_time: Thời gian chạy fuzzer.
        _depend_contracts: Danh sách các hợp đồng phụ thuộc.
         max_trans_length: Độ dài tối đa của chuỗi giao dịch.
        _constructor_args: Tham số khởi tạo cho constructor của hợp đồng.
        _solc_path: Đường dẫn tới trình biên dịch Solidity.
        _duplication: Tham số tùy chọn về nhân đôi giao dịch.
    '''
    depend_contracts_str = " ".join(_depend_contracts)
    constructor_str = " ".join(_constructor_args)
    cmd = (f"{PYTHON} {FUZZER}"
           f" -s {_file_path}"
           f" -c {_main_contract}"
           f" --solc v{solc_version}"
           f" --evm {evm_version}"
           f" -t {timeout}"
           f" --result fuzzer/result/res.json"
           f" --cross-contract 1"
           f" --open-trans-comp 1"
           f" --depend-contracts {depend_contracts_str}"
           f" --constructor-args {constructor_str}"
           f" --constraint-solving 1"
           f" --max-individual-length {max_individual_length}"
           f" --solc-path-cross {_solc_path}"
           f" --p-open-cross 80"
           f" --cross-init-mode 1"
           f" --trans-mode 1"
           f" --duplication {_duplication}")
    print(cmd)
    os.popen(cmd).readlines()  # run CrossFuzz.py
    return "fuzzer/result/res.json"


def test_run():
    # absolute path
    _file_path = "./examples/T.sol"
    _main_contract = "E"
    solc_version = "0.4.26"
    evm_version = "byzantium"
    timeout = 10
    solc_path = config.SOLC_BIN_PATH
    _depend_contracts, _sl = analysis_depend_contract(file_path=_file_path, _contract_name=_main_contract,
                                                      _solc_version=solc_version, _solc_path=solc_path)
    max_individual_length = 10
    _constructor_args = analysis_main_contract_constructor(file_path=_file_path, _contract_name=_main_contract, sl=_sl)
    run(_file_path, _main_contract, solc_version, evm_version, timeout, _depend_contracts, max_individual_length,
        _constructor_args, _solc_path=config.SOLC_BIN_PATH)


def cli():
    # Hiển thị hướng dẫn sử dụng khi không có đủ tham số hoặc gọi `-help`
    if len(sys.argv) < 10 or sys.argv[1] in ("-help", "--help"):
        print(
            f"Usage: python {sys.argv[0]} <file_path> <contract_name> <solc_version> <max_trans_length> "
            "<fuzz_time> <res_saved_path> <solc_path> <constructor_params_path> <trans_duplication>\n\n"
            "Arguments:\n"
            "  file_path             Path to the Solidity file to be fuzzed\n"
            "  contract_name         Name of the contract to be fuzzed\n"
            "  solc_version          Supported Solidity compiler version (0.4.24, 0.4.26, 0.6.12, 0.8.4)\n"
            "  max_trans_length      Maximum transaction length (e.g., 10)\n"
            "  fuzz_time             Fuzzing duration in seconds (e.g., 60)\n"
            "  res_saved_path        Path to save the result JSON (e.g., ./result.json)\n"
            "  solc_path             Path to the Solidity compiler (solc)\n"
            "  constructor_params_path Path to constructor parameters (e.g., 'auto' or './examples/p.json')\n"
            "  trans_duplication     Duplicate transactions: 0 (no), 1 (yes)\n"
        )
        sys.exit(1)  # Kết thúc chương trình khi hiển thị hướng dẫn

    # Gán các tham số
    p = sys.argv[1]  # sol file path, which is the file path to be fuzzed
    c_name = sys.argv[2]  # contract name, which is the contract to be fuzzed
    solc_version = sys.argv[3]  # only support 0.4.24, 0.4.26, 0.6.12, 0.8.4
    max_trans_length = int(sys.argv[4])  # max transaction length, e.g., 10
    fuzz_time = int(sys.argv[5])  # fuzz time, e.g., 60(s)
    res_saved_path = sys.argv[6]  # e.g., ./xxxx.json
    solc_path = sys.argv[7]  # solc path
    constructor_params_path = sys.argv[8]  # e.g., Auto or "examples/p.json"
    trans_duplication = sys.argv[9]  # e.g., 0 if you don't want to duplicate transactions, otherwise 1

    _depend_contracts, _sl = analysis_depend_contract(file_path=p, _contract_name=c_name, _solc_version=solc_version,
                                                      _solc_path=solc_path)
    if len(_depend_contracts) <= 0:
        print("No depend contracts")
        sys.exit(-1)
    if constructor_params_path != "auto":
        _constructor_args = []
        for p_name, p_detail in json.load(open(constructor_params_path, "r", encoding="utf-8")).items():
            _constructor_args.append(f"{p_name} {p_detail['type']} {p_detail['value']}")
    else:
        _constructor_args = analysis_main_contract_constructor(file_path=p, _contract_name=c_name, sl=_sl)
    if _constructor_args is None:
        print("No constructor")
        sys.exit(-2)
    res = run(p, c_name, solc_version, "byzantium",
              fuzz_time, _depend_contracts, max_trans_length, _constructor_args, _solc_path=solc_path,
              _duplication=trans_duplication)
    shutil.copyfile(res, res_saved_path)  # move result json file to the specified path


if __name__ == "__main__":
    PYTHON = "python3"  # your python3 path
    FUZZER = "fuzzer/main.py"  # your fuzzer path in this repo
    cli()
    # test_run()
