/*
A program that implements a BigInt class that handles large integers using a vector of chars
to store the digits.  The class overloads the operators for addition, subtraction, multiplication,
division, modulo, increment, and equality. It also has functions to calculate the Fibonacci
and Factorial of a BigInt using tail recursion.
*/

#include <iostream>
#include <vector>
#include <iomanip>
#include <climits>
using namespace std;

class BigInt{
    private:
        vector<char> v;
    public:
        BigInt(){}

        // Takes an int and converts to BigInt
        BigInt(int n){
            char digit;
            while (n>9){
                digit = n%10;
                n /= 10;
                v.push_back(digit);
            }
            digit = n;
            v.push_back(digit);
        }

        // Overloading the output operator to print the BigInt
        friend ostream & operator<<(ostream & out, const BigInt & n){
            if (n.v.size() <= 12){
                for(int i=n.v.size() - 1; i>=0; i--){
                out << (int)n.v[i];
                }
            } else{
                int exp = n.v.size() - 1;
                out << (int)n.v[exp];
                out << ".";
                for (int i=exp - 1; i>exp - 6; i--){
                    out << (int)n.v[i];
                }
                out << "e" << exp;
            }
            return out;
        }

        // Takes a string and converts to BigInt
        BigInt(string s){
            for (int i = s.length() - 1; i >= 0; i--){
                char digit = int(s[i]) - '0';
                v.push_back(digit);
            }

        }

        // Addition operator overloading for BigInt
        BigInt operator+(const BigInt & other) const{
            BigInt result;
            int carry = 0;
            int maxLength = max(v.size(), other.v.size());

            for (int i=0; i < maxLength || carry; i++){
                int sum = carry;

                if (i < v.size()){
                    sum += (int)v[i];
                }

                if (i < other.v.size()){
                    sum += (int)other.v[i];
                }
                result.v.push_back(sum % 10);
                carry = sum / 10;
            }
            return result;

        }

        // Subtraction operator overloading for BigInt
        BigInt operator-(const BigInt & other) const{
            BigInt result;
            int borrow = 0;
            int maxLength = max(v.size(), other.v.size());
            for (int i=0; i < maxLength; i++){
                int diff = 0;

                if (i < v.size()){
                    diff += (v[i]);
                }
                diff -= borrow;

                if (i < other.v.size()){
                    diff -= (other.v[i]);
                }

                if (diff < 0){
                    diff += 10;
                    borrow = 1;
                }
                else{
                    borrow = 0;
                }
                result.v.push_back(diff);
            }
            while (result.v.size() > 1 && result.v.back() == 0){
                    result.v.pop_back();
                }
            return result;
        }

        // Multiplication operator overloading for BigInt
        BigInt operator*(const BigInt & other) const{
            BigInt result(0);
            for (int i=0; i<(int)other.v.size(); i++){
                int carry = 0;
                BigInt row;

                for(int k=0; k<i; k++){
                    row.v.push_back(0);
                }
                for(int j=0; j<(int)v.size() || carry; j++){
                    int product = carry;

                    if (j < (int)v.size()){
                        product += (v[j]) * (other.v[i]);
                    }
                    row.v.push_back(product % 10);
                    carry = product / 10;
                }
                result = result + row;
            }
            return result;
        }

        // Division operator overloading for BigInt
        BigInt operator/(const BigInt n) const{
            if (n == BigInt(0)){
                throw runtime_error("Division by Zero");
            }
            if (*this < n){
                return BigInt(0);
            }
            BigInt quotient(0);
            BigInt temp = *this;

            while (n < temp || n == temp){
                temp = temp - n;
                quotient = quotient + BigInt(1);
            }
            return quotient;
        }

        // Less than operator overloading for BigInt
        bool operator<(const BigInt & other) const{
            if (v.size() != other.v.size()){
                return v.size() < other.v.size();
            }

            for (int i=v.size() - 1; i >=0; i--){
                if (v[i] != other.v[i]){
                    return v[i] < other.v[i];
                }
            }
            return false;
        }

        // Modulo operator overloading for BigInt
        BigInt operator%(const BigInt n) const{
            if (BigInt(0) == n){
                throw runtime_error("Division by Zero");
            }
            if (*this < n){
                return *this;
            }
            BigInt temp = *this;
            while (n < temp || n == temp){
                temp = temp - n;
            }
            return temp;
        }

        // Increment operator overloading for BigInt
        BigInt operator++(int){
            *this = *this + BigInt(1);
            return *this - BigInt(1);
        }

        // Pre-increment operator overloading for BigInt
        BigInt &operator++(){
        *this = *this + BigInt(1);
            return *this;
        }

        // Equality operator overloading for BigInt
        bool operator==(const BigInt & other) const{
            if (this->v.size() != other.v.size()){
                return false;
            }

            for (int i=0; i<v.size();i++){
                if (this->v[i] != other.v[i]){
                    return false;
                }
            }
            return true;
        }

        // Print function to display the BigInt
        void print(){
            for(int i=v.size() - 1; i>=0; i--){
                cout << (int)v[i];
            }
        }

        // Fibonacci function using tail recursion
        BigInt fiboHelper(BigInt a, BigInt b){
            if (*this == BigInt(0)){
                return a;
            }
            BigInt next = *this - BigInt(1);
            return next.fiboHelper(b, a + b);
        }

        // Tail recursive Fibonacci function that calls the helper function
        BigInt fibo(){
            return fiboHelper(BigInt(0), BigInt(1));
        }

        // Factorial function using tail recursion
        BigInt factHelper(BigInt n, BigInt result){
            if (n == BigInt(0) || n == BigInt(1)){
                return result;
            }
            BigInt nextN = n - BigInt(1);
            return nextN.factHelper(nextN, result * n);
        }

        // Tail recursive Factorial function that calls the helper function
        BigInt fact(){
            return factHelper(*this, BigInt(1));

        }
};

int main(){
    int space = 10;
    cout << "\a\nTestUnit:\n" << flush;
    cout << "User Name:" << flush;
    system("whoami");
    system("date");
    BigInt n1(25);
    BigInt s1("25");
    BigInt n2(1234);
    BigInt s2("1234");
    BigInt n3(n2);
    BigInt X(3000);
    BigInt Y(50);
    BigInt Z1(123);
    BigInt Z2("989345275647");
    BigInt Z3(X.fibo());
    BigInt imax = INT_MAX;
    BigInt big("9223372036854775807");

    cout << "n1(int)    :" << setw(space) << n1 << endl;
    cout << "s1(str)    :" << setw(space) << s1 << endl;
    cout << "n2(int)    :" << setw(space) << n2 << endl;
    cout << "s2(str)    :" << setw(space) << s2 << endl;
    cout << "n3(n2)     :" << setw(space) << n3 << endl;
    cout << "X.fibo(1234):" << setw(space) << X.fibo() << endl;
    cout << "Y.fact(50) :" << setw(space) << Y.fact() << endl;
    cout << "imax       :" << setw(space) << imax << endl;
    cout << "big        :" << setw(space) << big << endl;
    cout << "big.print(): "; big.print(); cout << endl;

    cout << n2 << "/" << n1 << " = " << n2/n1 <<" rem "<<n2%n1<<endl;
    cout << "fibo("<<X<<") = "<<X.fibo() << endl;
    cout << "fact("<<Y<<") = "<<Y.fact() << endl;

    cout << "10 + n1 = " << BigInt(10) + n1 << endl;
    cout << "n1 + 10 = " << n1 + BigInt(10) << endl;

    cout << "(n1 == s1)? --> "<<((n1==s1)?"true":"false")<<endl;
    cout << "n1++ = ? --> before:"<<n1++<<" after:" << n1 << endl;
    cout << "++s1 = ? --> before:"<<++s1<<" after:" << s1 << endl;

    cout << "s2 * big = ? --> " << s2 * big << endl;
    cout << "big * s2 = ? --> " << big * s2 << endl;

    cout << endl;
    system("date");

    return 0;
}