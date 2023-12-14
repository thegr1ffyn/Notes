'''
Python Code to find and plot time of Heap, Counting, Quick and Radix Sort
Developed by: Hamza Haroon 
Design and Analysis of Algorithms
'''

import random
import time
import matplotlib.pyplot as plt

def heapify(arr, n, i):
    largest = i
    left = 2 * i + 1
    right = 2 * i + 2

    if left < n and arr[i] < arr[left]:
        largest = left

    if right < n and arr[largest] < arr[right]:
        largest = right

    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]
        heapify(arr, n, largest)

def heap_sort(arr):
    n = len(arr)

    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i)

    for i in range(n - 1, 0, -1):
        arr[i], arr[0] = arr[0], arr[i]
        heapify(arr, i, 0)

def quick_sort(arr):
    if len(arr) <= 1:
        return arr

    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]

    return quick_sort(left) + middle + quick_sort(right)

def counting_sort(arr):
    max_val = max(arr)
    count = [0] * (max_val + 1)

    for num in arr:
        count[num] += 1

    sorted_arr = []
    for i in range(max_val + 1):
        sorted_arr.extend([i] * count[i])

    return sorted_arr

def radix_sort(arr):
    max_val = max(arr)
    exp = 1

    while max_val // exp > 0:
        counting_sort_by_digit(arr, exp)
        exp *= 10

def counting_sort_by_digit(arr, exp):
    n = len(arr)
    output = [0] * n
    count = [0] * 10

    for i in range(n):
        index = arr[i] // exp
        count[index % 10] += 1

    for i in range(1, 10):
        count[i] += count[i - 1]

    i = n - 1
    while i >= 0:
        index = arr[i] // exp
        output[count[index % 10] - 1] = arr[i]
        count[index % 10] -= 1
        i -= 1

    for i in range(n):
        arr[i] = output[i]

def generate_test_case(size):
    return [random.randint(1, 100000000) for _ in range(size)]

def measure_time_and_memory(func, *args):
    start_time = time.time()
    result = func(*args)
    end_time = time.time()
    memory_usage = 0  # Additional code needed to measure memory usage

    return result, end_time - start_time, memory_usage

# Comparison plot
input_sizes = [1, 1, 100, 1000, 5000, 10000, 20000, 40000, 80000, 100000, 250000, 5000000, 1000000, 10000000]

heap_sort_times = []
quick_sort_times = []
counting_sort_times = []
radix_sort_times = []

for size in input_sizes:
    random_array = generate_test_case(size)
    heap_sort_time = measure_time_and_memory(heap_sort, random_array.copy())[1]
    quick_sort_time = measure_time_and_memory(quick_sort, random_array.copy())[1]
    counting_sort_time = measure_time_and_memory(counting_sort, random_array.copy())[1]
    radix_sort_time = measure_time_and_memory(radix_sort, random_array.copy())[1]

    print("Number of values are ", size, " randomized multivalued cases")
    print("Heap Sort Time:", heap_sort_times, "seconds")
    print("Quick Sort Time:", quick_sort_times, "seconds")
    print("Counting Sort Time:", counting_sort_times, "seconds")
    print("Radix Sort Time:", radix_sort_times, "seconds\n\n")

    heap_sort_times.append(heap_sort_time)
    quick_sort_times.append(quick_sort_time)
    counting_sort_times.append(counting_sort_time)
    radix_sort_times.append(radix_sort_time)



plt.figure(figsize=(8, 6))
plt.plot(input_sizes, heap_sort_times, marker='o', label='Heap Sort')
plt.plot(input_sizes, quick_sort_times, marker='o', label='Quick Sort')
plt.plot(input_sizes, counting_sort_times, marker='o', label='Counting Sort')
plt.plot(input_sizes, radix_sort_times, marker='o', label='Radix Sort')
plt.xlabel('Input Size')
plt.ylabel('Execution Time (seconds)')
plt.title('Comparison of Sorting Algorithms')
plt.legend()
plt.grid(True)
plt.show()
