#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' Module for Genetic Algorithm mutation operator class '''

from ..metaclasses import MutationMeta
'''
Triển khai một lớp cơ sở (Mutation) để cung cấp giao diện (interface) cho các 
thao tác đột biến (mutation) trong thuật toán di truyền (Genetic Algorithm - GA)
'''


class Mutation(metaclass=MutationMeta):
    '''
    Lớp này không chứa logic cụ thể, mà được thiết kế như một lớp trừu tượng (abstract class), 
    giúp các lớp con có thể kế thừa và tùy chỉnh hành vi lai ghép theo nhu cầu riêng
    '''
    # Đại diện cho xác suất đột biến (probability of mutation)
    pm = 0.1 #là xác suất để một gen trong cá thể bị đột biến trong thuật toán di truyền

    def mutate(self, individual, engine):
        '''
        Called when an individual to be mutated.

        :param individual: The individual to be mutated.
        :type individual: subclass of IndvidualBase

        :param engine: The GA engine where the mutation operator belongs.
        :type engine: GAEngine
        '''
        raise NotImplementedError ##Dùng để thông báo rằng phương thức này phải được triển khai bởi các lớp con. Nếu không, việc gọi phương thức sẽ gây lỗi

