#ifndef __DG_UNIFORM_DISTRIBUTED_SYMMETRIC_ENCODER_H__
#define __DG_UNIFORM_DISTRIBUTED_SYMMETRIC_ENCODER_H__

#include <random>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <stdexcept>
#include "compact_serializer.h"

namespace dg::ud_sym_encoder{

    struct bad_encoding_format: std::exception{}; 
    struct invalid_argument: std::exception{}; 

    using mt19937 = std::mersenne_twister_engine<uint64_t, 64, 312, 156, 31,
                                                    0xb5026f5aa96619e9ULL, 29,
                                                    0x5555555555555555ULL, 17,
                                                    0x71d67fffeda60000ULL, 37,
                                                    0xfff7eee000000000ULL, 43,
                                                    6364136223846793005ULL>;

    struct EncoderInterface{
        virtual ~EncoderInterface() noexcept = default;
        virtual auto encode(const std::string&) -> std::string = 0;
        virtual auto decode(const std::string&) -> std::string = 0; 
    };

    struct MurMurMessage{
        uint64_t validation_key;
        std::string encoded;

        template <class Reflector>
        void dg_reflect(const Reflector& reflector) const{
            reflector(validation_key, encoded);
        }

        template <class Reflector>
        void dg_reflect(const Reflector& reflector){
            reflector(validation_key, encoded);
        }
    };

    class MurMurEncoder: public virtual EncoderInterface{

        private:

            uint64_t secret;

        public:

            MurMurEncoder(uint64_t secret) noexcept: secret(secret){}

            auto encode(const std::string& arg) -> std::string{

                uint64_t key    = dg::hasher::murmur_hash(arg.data(), arg.size(), this->secret);
                auto msg        = MurMurMessage{key, arg};
                auto bstream    = std::string(dg::compact_serializer::integrity_size(msg), ' ');
                dg::compact_serializer::integrity_serialize_into(bstream.data(), msg);

                return bstream;
            }

            auto decode(const std::string& arg) -> std::string{

                MurMurMessage msg{};
        
                try{
                    dg::compact_serializer::integrity_deserialize_into(msg, arg.data(), arg.size());
                } catch (dg::compact_serializer::bad_encoding_format& err){
                    throw bad_encoding_format();
                } catch (...){
                    std::rethrow_exception(std::current_exception());
                }

                uint64_t expected_key = dg::hasher::murmur_hash(msg.encoded.data(), msg.encoded.size(), this->secret);
                
                if (expected_key != msg.validation_key){
                    throw bad_encoding_format();
                }

                return msg.encoded;
            }
    };

    struct Mt19937Message{
        uint64_t salt;
        std::string encoded;

        template <class Reflector>
        void dg_reflect(const Reflector& reflector){
            reflector(salt, encoded);
        }

        template <class Reflector>
        void dg_reflect(const Reflector& reflector) const{
            reflector(salt, encoded);
        }
    };

    using mt19937 = std::mersenne_twister_engine<uint64_t, 64, 312, 156, 31,
                                                 0xb5026f5aa96619e9ULL, 29,
                                                 0x5555555555555555ULL, 17,
                                                 0x71d67fffeda60000ULL, 37,
                                                 0xfff7eee000000000ULL, 43,
                                                 6364136223846793005ULL>;

    class Mt19937Encoder: public virtual EncoderInterface{

        private:

            std::string secret;
            const size_t max_encoding_length;
            mt19937 salt_randgen;
            
        public:


            Mt19937Encoder(std::string secret,
                            size_t max_encoding_length,
                            mt19937 salt_randgen) noexcept: secret(std::move(secret)),
                                                            max_encoding_length(max_encoding_length),
                                                            salt_randgen(std::move(salt_randgen)){}

            auto encode(const std::string& arg) -> std::string{
                
                if (arg.size() > this->max_encoding_length){
                    throw invalid_argument();
                }

                uint64_t salt       = this->salt_randgen();
                uint64_t seed       = this->randomizer_seed(this->secret, salt);
                auto randomizer     = mt19937{seed};
                auto encoded        = std::string(arg.size(), ' ');

                for (size_t i = 0u; i < arg.size(); ++i){
                    encoded[i] = this->byte_encode(arg[i], randomizer);
                }

                auto msg            = Mt19937Message{salt, std::move(encoded)};
                auto bstream        = std::string(dg::compact_serializer::integrity_size(msg), ' ');
                dg::compact_serializer::integrity_serialize_into(bstream.data(), msg);

                return bstream; 
            }

            auto decode(const std::string& arg) -> std::string{

                Mt19937Message msg{};
                
                try{
                    dg::compact_serializer::integrity_deserialize_into(msg, arg.data(), arg.size());
                } catch (dg::compact_serializer::bad_encoding_format& err){
                    throw bad_encoding_format();
                } catch (...){
                    std::rethrow_exception(std::current_exception());
                }

                uint64_t seed       = this->randomizer_seed(this->secret, msg.salt);
                auto randomizer     = mt19937{seed};
                auto decoded        = std::string(msg.encoded.size(), ' ');

                for (size_t i = 0u; i < msg.encoded.size(); ++i){
                    decoded[i] = this->byte_decode(msg.encoded[i], randomizer);
                }

                return decoded;
            }
        
        private:

            auto randomizer_seed(const std::string& secret, uint64_t salt) noexcept -> uint64_t{
                
                std::string ss(dg::trivial_serializer::size(salt), ' ');
                dg::trivial_serializer::serialize_into(ss.data(), salt);
                std::string cat = secret + ss; 

                return dg::hasher::murmur_hash(cat.data(), cat.size());
            }

            template <class Randomizer>
            auto get_byte_dict(Randomizer& randomizer) noexcept -> std::vector<uint8_t>{
                
                std::vector<uint8_t> rs(256);
                std::iota(rs.begin(), rs.end(), 0u);

                for (size_t i = 0u; i < 256; ++i){
                    size_t lhs_idx = static_cast<size_t>(randomizer()) % 256;
                    size_t rhs_idx = static_cast<size_t>(randomizer()) % 256;
                    std::swap(rs[lhs_idx], rs[rhs_idx]);
                }

                return rs;
            }

            template <class Randomizer>
            auto byte_encode(char key, Randomizer& randomizer) noexcept -> char{

                std::vector<uint8_t> dict = get_byte_dict(randomizer);
                return std::bit_cast<char>(dict[std::bit_cast<uint8_t>(key)]);
            }

            template <class Randomizer>
            auto byte_decode(char value, Randomizer& randomizer) noexcept -> char{
                
                std::vector<uint8_t> dict = get_byte_dict(randomizer);
                uint8_t key = std::distance(dict.begin(), std::find(dict.begin(), dict.end(), std::bit_cast<uint8_t>(value)));

                return std::bit_cast<char>(key);
            }
    };

    class DoubleEncoder: public virtual EncoderInterface{

        private:

            std::unique_ptr<EncoderInterface> first_encoder;
            std::unique_ptr<EncoderInterface> second_encoder;
        
        public:

            DoubleEncoder(std::unique_ptr<EncoderInterface> first_encoder,
                            std::unique_ptr<EncoderInterface> second_encoder) noexcept: first_encoder(std::move(first_encoder)),
                                                                                        second_encoder(std::move(second_encoder)){}
            
            auto encode(const std::string& msg) -> std::string{
                
                return this->second_encoder->encode(this->first_encoder->encode(msg));
            }

            auto decode(const std::string& msg) -> std::string{

                return this->first_encoder->decode(this->second_encoder->decode(msg));
            }
    };

    auto spawn_encoder(const std::string& secret, size_t max_encoding_len) -> std::unique_ptr<EncoderInterface>{

        uint64_t uint_secret = dg::hasher::murmur_hash(secret.data(), secret.size());
        std::unique_ptr<EncoderInterface> integrity_encoder = std::make_unique<MurMurEncoder>(uint_secret);
        std::unique_ptr<EncoderInterface> unif_dist_encoder = std::make_unique<Mt19937Encoder>(secret, max_encoding_len, mt19937{}); 
        std::unique_ptr<EncoderInterface> combined_encoder  = std::make_unique<DoubleEncoder>(std::move(integrity_encoder), std::move(unif_dist_encoder));

        return combined_encoder;
    }
}



#endif