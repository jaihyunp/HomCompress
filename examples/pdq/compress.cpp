/* Copyright (C) 2020 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

// This is a sample program for education purposes only.
// It implements a very simple homomorphic encryption based
// db search algorithm for demonstration purposes.

// This country lookup example is derived from the BGV database demo
// code originally written by Jack Crawford for a lunch and learn
// session at IBM Research (Hursley) in 2019.
// The original example code ships with HElib and can be found at
// https://github.com/homenc/HElib/tree/master/examples/BGV_database_lookup

#include <iostream>

#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

int modpow(int a, int b, int p) {
    if (!b) 
        return 1;

    int res = modpow(a, b / 2, p);
    res = ((long long int) res * res) % p;

    if (b % 2)
        res = ((long long int) res * a) % p;
    
    return res;
}

int main(int argc, char* argv[])
{
    int logN = 14;
    int logs = 7;

    // Plaintext prime modulus
    unsigned long p = 65537;
    // Cyclotomic polynomial - defines phi(m)
    unsigned long m = 1 << 14; // this will give 48 slots
    // Hensel lifting (default = 1)
    unsigned long r = 1;
    // Number of bits of the modulus chain
    unsigned long bits = 100;
    // Number of columns of Key-Switching matrix (default = 2 or 3)
    unsigned long c = 1;
    // Size of NTL thread pool (default =1)
    unsigned long nthreads = 1;
    // input database file name
    std::string answer_file = "./ans.csv";
  
    helib::ArgMap amap;
    amap.arg("logN", logN, "bit-size of the database");
    amap.arg("logs", logs, "bit-size of the maximal query");
    amap.arg("nthreads", nthreads, "Size of NTL thread pool");
    amap.arg("ofile", answer_file, "the output plaintext");
    amap.parse(argc, argv);
  
    // set NTL Thread pool size
    if (nthreads > 1)
        NTL::SetNumThreads(nthreads);
  
    std::cout << "\n*********************************************************";
    std::cout << "\n*                Homomorphic Compression                *";
    std::cout << "\n*               =========================               *";
    std::cout << "\n*                                                       *";
    std::cout << "\n* This is a proof-of-concept implementatoin of CLPY.    *";
    std::cout << "\n* It compresses 2^logN vector with 2^logs sparsity.     *";
    std::cout << "\n*                                                       *";
    std::cout << "\n*********************************************************";
    std::cout << "\n" << std::endl;
  
    std::cout << "---Initialising HE Environment ... ";
    // Initialize context
    // This object will hold information about the algebra used for this scheme.
    std::cout << "\nInitializing the Context ... " << std::endl;
    HELIB_NTIMER_START(timer_Context);
    helib::Context context = helib::ContextBuilder<helib::BGV>()
                                 .m(m)
                                 .p(p)
                                 .r(r)
                                 .bits(bits)
                                 .c(c)
                                 .build();
    HELIB_NTIMER_STOP(timer_Context);
    helib::printNamedTimer(std::cout, "timer_Context");
  
    // Secret key management
    std::cout << "Creating Secret Key ..." << std::endl;
    HELIB_NTIMER_START(timer_SecKey);
    helib::SecKey secret_key = helib::SecKey(context);
    secret_key.GenSecKey();
    HELIB_NTIMER_STOP(timer_SecKey);
    helib::printNamedTimer(std::cout, "timer_SecKey");
  
    // Public key management
    std::cout << "Creating Public Key ..." << std::endl;
    // Compute key-switching matrices that we need
    HELIB_NTIMER_START(timer_SKM);
    helib::addSome1DMatrices(secret_key);
    HELIB_NTIMER_STOP(timer_SKM);
    helib::printNamedTimer(std::cout, "timer_SKM");
  
    // Set the secret key (upcast: FHESecKey is a subclass of FHEPubKey)
    HELIB_NTIMER_START(timer_PubKey);
    const helib::PubKey& public_key = secret_key;
    HELIB_NTIMER_STOP(timer_PubKey);
    helib::printNamedTimer(std::cout, "timer_PubKey");
  
    // Print the context
    std::cout << "\n---FHE Context: " << std::endl;
    context.printout();
    
    // Get the number of slot (phi(m))
    long nslots = m >> 1;
    int logr = logs + 1;
    int col = 1 << logN; 
    int row = 1 << logr;
    int maxg = 1 << (logr/2);
    int N = 1 << logN;
    int s = 1 << logs;
    std::cout << "\n---Homomorphic Compression Params: " << std::endl;
    std::cout << "* The number of total data: " << N << std::endl;
    std::cout << "* The sparsity: " << s << std::endl;
    std::cout << "* The number of slots in a BGV ctxt: " << nslots << std::endl;


    
    // Initialize data
    std::vector<int> data (N);
    for (int i = 0; i < N; i ++) {
        data[i] = (i + 101) % p;
    }



    // Generate the sparse input vector
    HELIB_NTIMER_START(timer_Query);
    std::vector<int> position = {
        1,12,123,1234,12345,2,23,234,2345,
        21,212,2123,21234,212345,22,223,2234,22345,
        31,312,3123,31234,312345,32,323,3234,32345,
        41,412,4123,41234,412345,42,423,4234,42345
        }; // This indicates the indices of non-zero elements in the sparse input vector. The index starts from 1.

    std::vector<helib::Ptxt<helib::BGV> > query;
    for (int i = 0; i < col / nslots; i ++) {
        helib::Ptxt<helib::BGV> query_single(context); 
        for (int i = 0; i < query_single.size(); i ++)
            query_single[i] = 0;
        query.push_back(query_single);
    }
    while (position.size() < 128) {
        position.push_back(random() % N);
    }
    for (int i = 0; i < s/2; i ++) { 
        int pos = (position[i] + N - 1) % N;
        int idx1 = pos / nslots;
        int idx2 = (pos % nslots) / (nslots / 2);
        int idx3 = pos % (nslots / 2);
        query[idx1][idx2 + 2 * idx3] = 1;
    }

    std::vector<helib::Ctxt> _query;
    for (int i = 0; i < col / nslots; i ++) {
        helib::Ctxt _query_single(public_key);
        public_key.Encrypt(_query_single, query[i]);
        _query.push_back(_query_single);
    }
    HELIB_NTIMER_STOP(timer_Query);
    


    // Tiling (Offline and reusuable)
    HELIB_NTIMER_START(timer_Tiling);
    std::vector<std::vector<helib::Ptxt<helib::BGV> > > matrix;
    for (int i = 0; i < col / nslots; i ++) {
        std::vector<helib::Ptxt<helib::BGV> > matrix_single;
        for (int j = 0; j < row; j ++) {
            helib::Ptxt<helib::BGV> matrix_row(context);

            for (int slot = 0; slot < nslots; slot ++) {
                int idxc = ((slot/2 + j) % (nslots/2) + (slot & 1) * nslots/2 + i*nslots) % col;
                int idxr = (i*nslots + (slot & 1) * nslots/2 + slot/2) % row;
                if (idxr < s) {
                    matrix_row[slot] = modpow(idxc + 1, idxr + 1, p);
                } else {
                    matrix_row[slot] = ((long long int) data[idxc] * modpow(idxc + 1, idxr - s + 1, p)) % p;
                }
            }
            matrix_single.push_back(matrix_row);
        }
        matrix.push_back(matrix_single);
    }
    HELIB_NTIMER_STOP(timer_Tiling);



    // Homomorphic Compression (Server-side Online)
    HELIB_NTIMER_START(timer_TotalQuery);
    helib::Ctxt zip(public_key);
    // For each sub-matrix,
    for (int i = 0; i < col / nslots; i ++) {

        // Baby-step
        std::vector<helib::Ctxt> rotated_query;
        for (int g = 0; g < maxg; g ++) { 
            if (g) {
                helib::Ctxt c_g (rotated_query[g - 1]);
                c_g.smartAutomorph(modpow(3, nslots/2 - 1, m)); 
                rotated_query.push_back(c_g);
            } else {
                helib::Ctxt c_g(_query[i]);
                rotated_query.push_back(c_g);
            }
        }

        helib::Ctxt product(public_key);
        // Giant-step
        for (int b = 0; b < row/maxg; b ++) { 
            helib::Ctxt giant(rotated_query[0]);
            for (int g = 0; g < maxg; g ++) {
                helib::Ctxt temp(rotated_query[g]);
                matrix[i][b*maxg + g].rotate(b*maxg*2); 
                if (!g) {
                    giant *= matrix[i][b*maxg+g];
                } else {
                    temp *= matrix[i][b*maxg+g];
                    giant += temp;
                }                
                matrix[i][b*maxg + g].rotate(-b*maxg*2); 
            }

            if(!b) {
                product = giant;
            } else {
                giant.smartAutomorph(modpow(3, nslots/2 - b*maxg, m));
                product += giant;
            }
        }
 
        // sum all
        helib::Ctxt res(product);
        for (int j = 0; j < log2(nslots) - 1 - logr; j ++) {
            helib::Ctxt temp(res);
            temp.smartAutomorph(modpow(3, row*pow(2,j), m));
            res += temp;
        }
        if (!i) {
            zip = res;
        } else {
            zip += res;
        } 
    }

    helib::Ctxt zip2(zip);
    zip2.smartAutomorph(m/2 - 1); 
    zip += zip2;
    HELIB_NTIMER_STOP(timer_TotalQuery);


    // Decrypt and Decode (Client-side Online)
    HELIB_NTIMER_START(timer_Decrypt);
    helib::Ptxt<helib::BGV> ptxt_res(context);
    secret_key.Decrypt(ptxt_res, zip);
    HELIB_NTIMER_STOP(timer_Decrypt);


    // For the downstream task (see decompress.sage)
    std::ofstream file;
    file.open(answer_file);
    for (int i = 0; i < row; i ++) {
        file << ptxt_res[2*i];
        if (i != row - 1)
            file << ",";
        else
            file << std::endl;
    }
    file.close();

    std::cout << "\n--- Timing" << std::endl;
    std::cout << "* Homomorphic Compression" << std::endl;
    helib::printNamedTimer(std::cout, "timer_Tiling");
    helib::printNamedTimer(std::cout, "timer_TotalQuery");
    
    std::cout << "* Decompression" << std::endl;
    helib::printNamedTimer(std::cout, "timer_Decrypt");
    
    return 0;
}
