#include "ud_sym_encoder.h"
#include <iostream>
#include <random> 
#include <utility>
#include <functional>

int main(){
    
    //tested + verified for g++-13 main.cpp -O3 -std=c++23

    std::unique_ptr<dg::ud_sym_encoder::EncoderInterface> encoder = dg::ud_sym_encoder::spawn_encoder("my_secret_should_be_1<<30_in_length");
    auto rand_gen   = std::bind(std::uniform_int_distribution<char>{}, std::mt19937{});
    auto sz_gen     = std::bind(std::uniform_int_distribution<uint8_t>{}, std::mt19937{}); 

    while (true){
        std::string inp(sz_gen(), ' ');
        std::generate(inp.begin(), inp.end(), std::ref(rand_gen));
        std::string out = encoder->decode(encoder->encode(inp));

        if (inp != out){
            std::cout << "mayday" << std::endl;
        }
    }
}