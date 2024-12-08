#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import random

from fuzzer.utils import settings


class Individuals(object):
    '''
    Có chức năng định nghĩa lớp Individuals, là một descriptor được sử dụng để quản lý 
    các cá thể trong quần thể trong quá trình fuzzing hoặc thuật toán tiến hóa.
    '''

    def __init__(self, name): # Khởi tạo một descriptor mới với tiền tố là "_"
        self.name = '_{}'.format(name)

    def __get__(self, instance, owner): # Truy xuất giá trị của thuộc tính descriptor từ đối tượng (instance) thông qua __dict__
        return instance.__dict__[self.name]

    def __set__(self, instance, value): # Gán giá trị cho thuộc tính descriptor thông qua __dict__
        instance.__dict__[self.name] = value
        # Update flag.
        instance.update_flag()


class Population(object):
    """
    Được sử dụng để tạo một tập hợp các trường hợp kiểm thử.
    individuals chính là nhiều chuỗi giao dịch.
    """
    # All individuals.
    individuals = Individuals('individuals')

    def __init__(self, indv_template, indv_generator, size=100, other_generators=None):
        '''
        Lớp đại diện cho quần thể trong thuật toán di truyền.

        :indv_template: Một mẫu cá thể được dùng để nhân bản tất cả các cá thể khác trong quần thể hiện tại.
        :size: Kích thước quần thể, số lượng cá thể trong quần thể.
        
        :Kiểu dữ liệu: int.

        '''
        # Population size.
        if size % 2 != 0:
            raise ValueError('Population size must be an even number')
        self.size = size

        # Đối tượng mẫu.
        self.indv_template = indv_template

        # Đối tượng tạo cá thể.
        self.indv_generator = indv_generator

        # Cờ để giám sát các thay đổi trong quần thể.
        self._updated = False

        # Bộ chứa cho tất cả các cá thể.
        class IndvList(list):
            '''
            Một lớp proxy kế thừa từ danh sách tích hợp sẵn (built-in list) để chứa tất cả các cá thể.
            Lớp này có thể tự động cập nhật cờ population._updated khi nội dung của nó thay đổi.
            '''

            # LƯU Ý: Sử dụng 'this' ở đây để tránh xung đột tên.
            def __init__(this, *args): # Khởi tạo một danh sách mới với các cá thể.
                super(this.__class__, this).__init__(*args)

            """def __setitem__(this, key, value):
                '''
                Ghi đè phương thức __setitem__ trong kiểu danh sách tích hợp sẵn.
                Dùng để gán giá trị mới vào một chỉ số trong danh sách.
                '''
                
                old_value = this[key]
                if old_value == value:
                    return
                super(this.__class__, self).__setitem__(key, value)
                # Update population flag.
                self.update_flag()"""

            def append(this, item):
                '''
                Ghi đè phương thức append của kiểu danh sách tích hợp sẵn.
                Dùng để thêm một phần tử mới vào cuối danh sách.
                '''
                
                super(this.__class__, this).append(item)
                # Update population flag.
                self.update_flag()

            def extend(this, iterable_item):
                '''
                Ghi đè phương thức extend của kiểu danh sách tích hợp sẵn.
                Dùng để thêm một danh sách các phần tử vào danh sách hiện tại.
                '''
                
                if not iterable_item:
                    return
                super(this.__class__, this).extend(iterable_item)
                # Update population flag.
                self.update_flag()
            # }}}

        self._individuals = IndvList()

        self.other_generators = other_generators if other_generators is not None else []

    def init(self, indvs=None, init_seed=False, no_cross=False):
        '''
        Khởi tạo quần thể hiện tại với các cá thể.

        :param indvs: Danh sách các cá thể ban đầu trong quần thể. 
                    Nếu không được cung cấp, các cá thể sẽ được khởi tạo ngẫu nhiên.
        :param init_seed: Đánh dấu để khởi tạo dựa trên seed (giống hạt giống ngẫu nhiên).
        :param no_cross: Đánh dấu ngăn chặn việc kết hợp giữa các cá thể.
        :type indvs: list chứa các đối tượng Individual.
        
        '''
        IndvType = self.indv_template.__class__

        if indvs is None:
            if init_seed:
                for g in self.other_generators + [self.indv_generator]:
                    for func_hash, func_args_types in g.interface.items():
                        indv = IndvType(generator=g, other_generators=g.other_generators).init(func_hash=func_hash, func_args_types=func_args_types, default_value=True)
                        if len(indv.chromosome) == 0:  # Dãy giao dịch được sinh ra là rỗng, giao dịch giữa các hợp đồng đã sử dụng hết
                            if len(self.individuals) % 2 != 0:
                                indv_single = IndvType(generator=g, other_generators=g.other_generators).init(single=True, func_hash=func_hash, func_args_types=func_args_types, default_value=True)
                                self.individuals.append(indv_single)
                            else:
                                break
                        else:
                            self.individuals.append(indv)
            else:
                while len(self.individuals) < self.size:
                    chosen_generator = self.indv_generator
                    indv = IndvType(generator=chosen_generator, other_generators=chosen_generator.other_generators).init(no_cross=no_cross)
                    if len(indv.chromosome) == 0:  # Dãy giao dịch được sinh ra là rỗng, giao dịch giữa các hợp đồng đã sử dụng hết
                        if len(self.individuals) % 2 != 0:
                            indv_single = IndvType(generator=chosen_generator, other_generators=chosen_generator.other_generators).init(single=True, no_cross=no_cross)
                            self.individuals.append(indv_single)
                        else:
                            break
                    else:
                        self.individuals.append(indv)
        else:
            # Check individuals.
            if len(indvs) != self.size:
                raise ValueError('Invalid individuals number')
            for indv in indvs:
                if not isinstance(indv, SessionIndividual):
                    raise ValueError('individual class must be Individual or a subclass of Individual')
            self.individuals = indvs

        self._updated = True
        self.size = len(self.individuals)
        return self

    def update_flag(self):
        '''
        Đánh dấu quần thể đã được cập nhật.
        '''
        self._updated = True

    @property
    def updated(self):
        '''
        Kiểm tra trạng thái của cờ cập nhật.
        '''
        return self._updated

    def new(self):
        '''
        Tạo một quần thể mới rỗng với cùng cấu hình.
        '''
        return self.__class__(indv_template=self.indv_template, size=self.size, indv_generator=self.indv_generator, other_generators=self.other_generators)

    def __getitem__(self, key):
        '''
        Truy cập một cá thể trong quần thể bằng chỉ số.
        '''
        if key < 0 or key >= self.size:
            raise IndexError('Individual index({}) out of range'.format(key))
        return self.individuals[key]

    def __len__(self):
        '''
        Trả về số lượng cá thể trong quần thể.
        '''
        return len(self.individuals)

    def best_indv(self, fitness):
        '''
        Lấy cá thể có độ thích nghi tốt nhất trong quần thể.

        '''
        all_fits = self.all_fits(fitness)
        return max(self.individuals, key=lambda indv: all_fits[self.individuals.index(indv)])

    def worst_indv(self, fitness):
        '''
        Lấy cá thể có độ thích nghi kém nhất trong quần thể.
        '''
        all_fits = self.all_fits(fitness)
        return min(self.individuals, key=lambda indv: all_fits[self.individuals.index(indv)])

    def max(self, fitness):
        '''
        Lấy giá trị fitness cao nhất trong quần thể.
        '''
        return max(self.all_fits(fitness))

    def min(self, fitness):
        '''
        Lấy giá trị fitness thấp nhất trong quần thể.
        '''
        return min(self.all_fits(fitness))

    def mean(self, fitness):
        '''
        Tính giá trị trung bình của fitness trong quần thể.
        '''
        all_fits = self.all_fits(fitness)
        return sum(all_fits) / len(all_fits)

    def all_fits(self, fitness):
        '''
        Lấy danh sách giá trị fitness của tất cả các cá thể trong quần thể.
        '''
        return [fitness(indv) for indv in self.individuals]
