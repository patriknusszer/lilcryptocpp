//
//  main.cpp
//  lilcryptocpp
//
//  Created by Patrik Nusszer on 2020. 07. 27..
//  Copyright © 2020. Patrik Nusszer. All rights reserved.
//

#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>

using namespace std;
using namespace std::filesystem;

void xorcodebeta(string filep, string keyp, string outp, int chunksz, bool xnor) {
    if (file_size(filep) == 0 || file_size(keyp) == 0)
        return;
    
    ifstream file = ifstream(filep);
    ifstream key = ifstream(keyp);
    size_t ksz = file_size(keyp);
    ofstream chip = ofstream(outp);
    
    char *fchunk = (char*)malloc(sizeof(char) * chunksz);
    char *kchunk = (char*)malloc(sizeof(char) * chunksz);
    
    int rfchunksz, rkchunksz, fchunki, kchunki;
    rfchunksz = rkchunksz = fchunki = kchunki = 0;
    
    file.read(fchunk, chunksz);
    key.read(kchunk, chunksz);
    rfchunksz = (int)file.gcount();
    rkchunksz = (int)key.gcount();
    
    do {
        fchunk[fchunki] ^= kchunk[kchunki];
        
        if (xnor)
            fchunk[fchunki] = ~fchunk[fchunki];
        
        fchunki = (fchunki + 1) % rfchunksz;
        kchunki = (kchunki + 1) % rkchunksz;
        
        if (fchunki == 0) {
            chip.write(fchunk, rfchunksz);
            file.read(fchunk, chunksz);
            rfchunksz = (int)file.gcount();
            
            if (rfchunksz == 0)
                break;
        }
        
        if (kchunki == 0 && ksz > chunksz) {
            key.read(kchunk, chunksz);
            rkchunksz = (int)key.gcount();
            
            if (rkchunksz == 0) {
                key.clear();
                key.seekg(0, ios_base::beg);
                key.read(kchunk, chunksz);
                rkchunksz = (int)key.gcount();
            }
            else if (rkchunksz != chunksz)
                key.seekg(0, ios_base::beg);
        }
    } while (true);
    
    chip.flush();
    chip.close();
    file.close();
    key.close();
}

void keyget(ifstream &f, size_t &fsz, unsigned int chunksz, char *chunk, size_t offset) {
    if (offset != -1) {
        f.clear();
        f.seekg(offset, ios_base::beg);
    }
    
    f.read(chunk, chunksz);
    unsigned int read = (unsigned int)f.gcount();
    chunksz -= read;
    
    if (chunksz != 0) {
        f.clear();
        f.seekg(0, ios_base::beg);
        unsigned int wholeTimes = chunksz / fsz;
        char key[fsz];
        
        if (wholeTimes > 0) {
            f.read(key, fsz);
            
            for (unsigned int i = 0; i < wholeTimes; i++) {
                memcpy(chunk + read + (i * fsz), key, fsz);
                chunksz -= fsz;
            }
        }
        
        f.seekg(0, ios_base::beg);
        f.read(key, chunksz);
        memcpy(chunk + read + (wholeTimes * fsz), key, chunksz);
    }
}

void xorcode(string filep, string keyp, string outp, unsigned int chunksz, bool xnor) {
    size_t fsz = file_size(filep);
    size_t ksz = file_size(keyp);
    
    if (fsz == 0 || ksz == 0)
        return;
    
    ifstream file = ifstream(filep);
    ifstream key = ifstream(keyp);
    ofstream chip = ofstream(outp);
    char *fchunk = (char*)malloc(sizeof(char) * chunksz);
    char *kchunk = (char*)malloc(sizeof(char) * chunksz);
    
    do {
        file.read(fchunk, chunksz);
        
        if (file.gcount() == 0)
            break;
        
        keyget(key, ksz, (unsigned int)file.gcount(), kchunk, -1);
        
        for (unsigned int i = 0; i < file.gcount(); i++) {
            fchunk[i] ^= kchunk[i];
            
            if (xnor)
                fchunk[i] = ~fchunk[i];
        }
        
        chip.write(fchunk, file.gcount());
    } while (true);
    
    chip.flush();
    chip.close();
    file.close();
    key.close();
}

void gen(string path, size_t bytes) {
    ofstream f = ofstream(path);
    srand((unsigned int)time(0));
    int buff;
    
    for (size_t i = 0; i < bytes / sizeof(int); i++) {
        buff = rand();
        f.write((char*)&buff, sizeof(int));
    }
    
    int rem = bytes % 4;
    
    if (rem != 0) {
        buff = rand();
        f.write((char*)&buff, rem);
    }
    
    f.flush();
    f.close();
}

int main(int argc, const char * argv[]) {
    if (argc != 1) {
        if (strcmp(argv[2], "crypt")) {
            int chunksz;
            sscanf(argv[4], "%d", &chunksz);
            int xnor;
            sscanf(argv[5], "%d", &xnor);
            xorcode(string(argv[1]), string(argv[2]), string(argv[3]), chunksz, ~xnor);
        }
        else {
            size_t bytes;
            sscanf(argv[2], "%zu", &bytes);
            gen(string(argv[1]), bytes);
        }
    }
    else {
        string filep;
        cout << "File: ";
        cin >> filep;
        cout << "Key: ";
        string keyp;
        cin >> keyp;
        string outp;
        cout << "Output: ";
        cin >> outp;
        cout << "Chunk size: ";
        int chunksz;
        cin >> chunksz;
        cout << "xor (or xnor)?: ";
        bool x;
        cin >> x;
        xorcode(filep, keyp, outp, chunksz, !x);
    }
    
    return 0;
}
