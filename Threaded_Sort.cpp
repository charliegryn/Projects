/*
A sorting program that uses bubble sort and threads to sort a dynamic array of unsorted integers 
generated from a generate.cpp file using a shell script.
*/

#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
using namespace std;

const int TOTAL_NUMBERS = 1000000;
const int TOTAL_NUMBERS_TEST = 10000;
const int NUM_THREADS = 16; 

long long totalSwaps = 0; // Global variable to count total swaps
mutex swapMutex; // Mutex to protect access to totalSwaps


int *nums = nullptr;

void bubbleSort(int *arr, int size, string name) {
    long long swaps = 0; // Local variable to count swaps for this thread
    for (int i = 0; i < size - 1; i++) {
        bool swapped = false;
        for (int j = 0; j < size - 1 - i; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp   = arr[j];
                arr[j]     = arr[j + 1];
                arr[j + 1] = temp;
                swaps++;
                swapped = true;
            }
        }
        if (!swapped) break;
    }

    swapMutex.lock();
    cout << name << " swap count: " << swaps << endl;
    totalSwaps += swaps;
    swapMutex.unlock();
}

void merge(int *a1, int s1, int *a2, int s2) {
    int *temp = new int[s1 + s2];
    
    int i = 0, j = 0, k = 0;

    while (i < s1 && j < s2) {
        if (a1[i] < a2[j]) {
            temp[k++] = a1[i++];
        } else {
            temp[k++] = a2[j++];
        }
    }

    while (i < s1) {
        temp[k++] = a1[i++];
    }
    while (j < s2) {
        temp[k++] = a2[j++];
    }

    for (int l = 0; l < s1 + s2; l++) {
        a1[l] = temp[l];
    }

    delete[] temp;
}

int main(int argc, char *argv[]) {
    // Check for correct number of command-line arguments
    if (argc < 3 || argc > 4) {
        cout << "Usage: " << argv[0] << " <inputFile> <outputFile> [-test]" << endl;
        return 1;
    }

    bool testMode = false;
    if (argc == 4 && string(argv[3]) == "-test") {
        testMode = true;
    }

    int TOTAL = testMode ? TOTAL_NUMBERS_TEST : TOTAL_NUMBERS;
    int SIZE = TOTAL / NUM_THREADS;

    // Allocate memory for the array of numbers
    nums = new int[TOTAL];

    // Open the input file and read numbers into the array
    ifstream inputFile(argv[1]);
    if (!inputFile) {
        cerr << "Error opening input file: " << argv[1] << endl;
        delete [] nums;
        return 1;
    }

    // Read numbers from the file into the array
    int count = 0;
    while (count < TOTAL && inputFile >> nums[count]) {
        count++;
    }
    inputFile.close();

    // Create pointers for each thread to sort its segment of the array
    int *ptr[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        ptr[i] = nums + i * SIZE;
    }

    // Create threads to sort segments of the array
    thread myThreads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        string name = "Thread " + to_string(i);
        int numElements = (i == NUM_THREADS - 1) ? (TOTAL - i * SIZE) : SIZE;
        myThreads[i] = thread(bubbleSort, ptr[i], numElements, name);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        myThreads[i].join();
    }
    
    cout << "Total swaps: " << totalSwaps << endl;

    // Merge sorted segments
    int numSegments = NUM_THREADS;
    int segmentSize = SIZE;

    while (numSegments > 1) {
        int newNumSegments = 0;
        for (int i = 0; i < numSegments - 1; i += 2) {
            int *left = nums + (i * segmentSize);
            int *right = left + segmentSize;
            int rightSize = segmentSize;

            if (right + rightSize > nums + TOTAL) {
                rightSize = (nums + TOTAL) - right;
            }

            merge(left, segmentSize, right, rightSize);
            newNumSegments++;
        }
        numSegments = newNumSegments;
        segmentSize *= 2;
    }

    ofstream outputFile(argv[2]);
    if (!outputFile) {
        cerr << "Error opening output file: " << argv[2] << endl;
        delete[] nums;
        return 1;
    }

    for (int i = 0; i < count; i++) {
        outputFile << nums[i] << endl;
    }
    outputFile.close();

    delete [] nums;
    nums = nullptr;

    return 0;
}