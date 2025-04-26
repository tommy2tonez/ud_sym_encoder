#include "ud_sym_encoder.h"
#include <iostream>
#include <random> 
#include <utility>
#include <functional>

int main(){

    //alright, I was thinking about this again
    //secret -> sub_secret -> token
    //compromise points: sub_secret, secret
    //sub_secret compromised -> token decoded
    //secret compromised -> foreign injections
    //sub_secret is our only weakness
    //for every generated token, we are decreasing one byte of secret trustworthiness, and one byte of subsecret trustworthiness
    //this is the base rule of token generation
    //we need to allow the flex_length of subsecret to protect user data, we establish pre-connected secret protocols (before we even communicate, public private asymmetric key pairs dont work)
    //we'll fix some of the fundamentals to integrate this into our system

    //tested + verified for g++-13 main.cpp -O3 -std=c++23
    //I've tried to think of every useful scenerios for asymmetric keys and there's none
    //the fundamental concept of asymmetric is very broken
    //it's possible to decode/decrypt the msg by using the public key - ask AI - don't even argue
    //the fundamental concept of encoding is symmetric and uniform distribution, if it's skewed, it's bad

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