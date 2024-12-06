#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def fitness_function(indv, env):
    """
    Tính toán độ thích nghi của một cá thể dựa trên độ phủ nhánh (branch coverage) 
    và phụ thuộc dữ liệu (data dependency)
    """
    "Tính toán độ phủ nhánh"
    block_coverage_fitness = compute_branch_coverage_fitness(env.individual_branches[indv.hash], env.code_coverage)
    "Nếu môi trường có phụ thuộc dữ liệu => tính toán phụ thuộc dữ liệu và cộng kết quả vào độ phủ nhánh"
    if env.args.data_dependency:
        data_dependency_fitness = compute_data_dependency_fitness(indv, env.data_dependencies)
        return block_coverage_fitness + data_dependency_fitness
    return block_coverage_fitness

    """
    Hàm tính toán số lượng nhánh code chưa được thăm bởi cá thể
        + branches: Danh sách các nhánh code liên quan đến cá thể
        + pcs: Danh sách các địa chỉ nhảy đã được thăm.
    """
def compute_branch_coverage_fitness(branches, pcs):
    non_visited_branches = 0.0
    "Duyệt qua các nhánh và đếm số lượng nhánh chưa được thăm và không có trong pcs"
    for jumpi in branches:
        for destination in branches[jumpi]:
            if not branches[jumpi][destination] and destination not in pcs:  # 如果分支没有被访问过, 并且目标地址不在pcs中
                # 这里统计的是, 测试用例没有覆盖的分支个数
                non_visited_branches += 1

    return non_visited_branches

    """
    Hàm tính toán độ phù hợp dựa trên phụ thuộc dữ liệu
        + indv: Cá thể, với thông tin về các gen trong nhiễm sắc thể
        + data_dependencies: Danh sách phụ thuộc dữ liệu (các biến "read" và "write")
    """
def compute_data_dependency_fitness(indv, data_dependencies):
    data_dependency_fitness = 0.0
    all_reads = set()
    "Tạo một tập hợp tất cả các thao tác đọc từ data_dependencies" 
    for d in data_dependencies:
        all_reads.update(data_dependencies[d]["read"])  # 将所有read的元素集合, 添加到all_reads中
    """
    Duyệt qua các nhiễm sắc thể (chromosome) của cá thể và kiểm tra xem các thao tác ghi có nằm trong 
    tập hợp các thao tác đọc hay không. Nếu có, tăng giá trị độ thích nghi phụ thuộc dữ liệu
    """
    for i in indv.chromosome:
        _function_hash = i["arguments"][0]
        if _function_hash in data_dependencies:
            for i in data_dependencies[_function_hash]["write"]:
                if i in all_reads:
                    data_dependency_fitness += 1

    return data_dependency_fitness
