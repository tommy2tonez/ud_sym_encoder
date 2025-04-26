#ifndef __DG_compact_serializer_H__
#define __DG_compact_serializer_H__

//define HEADER_CONTROL 2

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <climits>
#include <bit>
#include <optional>
#include <numeric>
#include "hasher.h"
#include <type_traits>
#include <array>

namespace dg::compact_serializer::constants{

    static constexpr auto endianness                            = std::endian::little;
    static constexpr bool IS_SAFE_INTEGER_CONVERSION_ENABLED    = true;
}

namespace dg::compact_serializer::types{

    using hash_type     = std::pair<uint64_t, uint64_t>; //alright this seems silly, we are to increase the chances of 10 ** 18 -> 10 ** 39 (never gonna happen), we actually chance better than RAM https://www.cs.toronto.edu/~bianca/papers/sigmetrics09.pdf, https://en.wikipedia.org/wiki/ECC_memory
                                                         //the only way to be successful in the career is to not trust everything, assume we are to deploy a massive 1 billion devices training system, we are gonna see errors very often
    using size_type     = uint64_t;
}

namespace dg::compact_serializer::exception_space{

    struct corrupted_format: std::exception{

        inline auto what() const noexcept -> const char *{

            return "corrupted_format";
        }
    };
}

namespace dg::compact_serializer::types_space{

    static constexpr auto nil_lambda    = [](...){}; 

    template <class T, class = void>
    struct is_tuple: std::false_type{};
    
    template <class T>
    struct is_tuple<T, std::void_t<decltype(std::tuple_size<T>::value)>>: std::true_type{};

    template <class T>
    struct is_unique_ptr: std::false_type{};

    template <class T>
    struct is_unique_ptr<std::unique_ptr<T>>: std::bool_constant<!std::is_array_v<T>>{}; 

    template <class T>
    struct is_optional: std::false_type{};

    template <class ...Args>
    struct is_optional<std::optional<Args...>>: std::true_type{}; 

    template <class T>
    struct is_vector: std::false_type{};

    template <class ...Args>
    struct is_vector<std::vector<Args...>>: std::true_type{};

    template <class T>
    struct is_unordered_map: std::false_type{};

    template <class ...Args>
    struct is_unordered_map<std::unordered_map<Args...>>: std::true_type{}; 

    template <class T>
    struct is_unordered_set: std::false_type{};

    template <class ...Args>
    struct is_unordered_set<std::unordered_set<Args...>>: std::true_type{};

    template <class T>
    struct is_map: std::false_type{};

    template <class ...Args>
    struct is_map<std::map<Args...>>: std::true_type{}; 
    
    template <class T>
    struct is_set: std::false_type{};

    template <class ...Args>
    struct is_set<std::set<Args...>>: std::true_type{};

    template <class T>
    struct is_basic_string: std::false_type{};

    template <class ...Args>
    struct is_basic_string<std::basic_string<Args...>>: std::true_type{};

    template <class T, class = void>
    struct is_reflectible: std::false_type{};

    template <class T>
    struct is_reflectible<T, std::void_t<decltype(std::declval<T>().dg_reflect(nil_lambda))>>: std::true_type{};
    
    template <class T, class = void>
    struct is_dg_arithmetic: std::is_arithmetic<T>{};

    template <class T>
    struct is_dg_arithmetic<T, std::void_t<std::enable_if_t<std::is_floating_point_v<T>>>>: std::bool_constant<std::numeric_limits<T>::is_iec559>{}; 
 
    template <class T>
    struct is_byte_stream_container: std::false_type{};

    template <class ...Args>
    struct is_byte_stream_container<std::vector<char, Args...>>: std::true_type{};

    template <class ...Args>
    struct is_byte_stream_container<std::basic_string<char, Args...>>: std::true_type{};

    template <class T, class = void>
    struct container_value_or_empty{};

    template <class T>
    struct container_value_or_empty<T, std::void_t<typename T::value_type>>{
        using type = typename T::value_type;
    };

    template <class T, class = void>
    struct container_bucket_or_empty{};

    template <class T>
    struct container_bucket_or_empty<T, std::void_t<typename T::key_type, typename T::mapped_type>>{
        using type = std::pair<typename T::key_type, typename T::mapped_type>; //I dont want to complicate this further by adding const to key_type (since this is an application) - 
    };

    template <class T>
    using containee_or_none_t = std::conditional_t<std::disjunction_v<is_vector<T>, is_unordered_set<T>, is_set<T>, is_basic_string<T>>,
                                                                      container_value_or_empty<T>,
                                                                      std::conditional_t<std::disjunction_v<is_unordered_map<T>, is_map<T>>, 
                                                                                         container_bucket_or_empty<T>, 
                                                                                         void>>;

    template <class T>
    using containee_t = typename containee_or_none_t<T>::type;

    template <class T, class = void>
    struct containee_or_empty{
        using type = void;
    };

    template <class T>
    struct containee_or_empty<T, std::void_t<containee_t<T>>>{
        using type = containee_t<T>;
    };

    template <class T>
    using containee_or_empty_t = typename containee_or_empty<T>::type; 

    //see: https://en.cppreference.com/w/cpp/language/types

    template <class T>
    static inline constexpr bool has_unique_serializable_representations_v              = std::disjunction_v<std::is_same<T, int8_t>, std::is_same<T, uint8_t>, 
                                                                                                             std::is_same<T, char>, std::is_same<T, unsigned char>, std::is_same<T, signed char>>;

    template <class T>
    static inline constexpr bool has_unique_serializable_sameendian_representations_v   = std::disjunction_v<std::is_same<T, int8_t>, std::is_same<T, uint8_t>, 
                                                                                                             std::is_same<T, char>, std::is_same<T, unsigned char>, std::is_same<T, signed char>,
                                                                                                             std::is_same<T, int16_t>, std::is_same<T, uint16_t>, 
                                                                                                             std::is_same<T, int32_t>, std::is_same<T, uint32_t>, 
                                                                                                             std::is_same<T, int64_t>, std::is_same<T, uint64_t>>;

    template <class T>
    static inline constexpr bool is_cpyable_linear_container_v                          = std::disjunction_v<is_vector<T>, is_basic_string<T>> && (has_unique_serializable_representations_v<containee_or_empty_t<T>> || has_unique_serializable_sameendian_representations_v<containee_or_empty_t<T>> && (std::endian::native == constants::endianness)); //this requires inter-compatible with noncpyable_linear

    template <class T>
    static inline constexpr bool is_noncpyable_linear_container_v                       = std::disjunction_v<is_vector<T>, is_basic_string<T>> && !is_cpyable_linear_container_v<T>;

    template <class T>
    static inline constexpr bool is_nonlinear_container_v                               = std::disjunction_v<is_unordered_map<T>, is_map<T>, is_set<T>>;

    template <class T>
    static inline constexpr bool is_tuple_v                                             = is_tuple<T>::value; 

    template <class T>
    static inline constexpr bool is_unique_ptr_v                                        = is_unique_ptr<T>::value;

    template <class T>
    static inline constexpr bool is_optional_v                                          = is_optional<T>::value;

    template <class T>
    static inline constexpr bool is_reflectible_v                                       = is_reflectible<T>::value;

    template <class T>
    static inline constexpr bool is_dg_arithmetic_v                                     = is_dg_arithmetic<T>::value;

    template <class T>
    static inline constexpr bool is_byte_stream_container_v                             = is_byte_stream_container<T>::value;

    template <class T>
    struct base_type: std::enable_if<true, T>{};

    //alright, I dont really know if this is future-proof, let's make it defined by using defined use-cases for now, we dont have time to iterate through every possibility
    template <class T>
    struct base_type<const T>: base_type<T>{};

    template <class T>
    struct base_type<volatile T>: base_type<T>{};

    template <class T>
    struct base_type<T&>: base_type<T>{};

    template <class T>
    struct base_type<T&&>: base_type<T>{};

    template <class T>
    using base_type_t = typename base_type<T>::type;
}

namespace dg::compact_serializer::utility{

    using namespace compact_serializer::types;

    struct SyncedEndiannessService{
        
        static constexpr auto is_native_big      = bool{std::endian::native == std::endian::big};
        static constexpr auto is_native_little   = bool{std::endian::native == std::endian::little};
        static constexpr auto precond            = bool{(is_native_big ^ is_native_little) != 0};
        static constexpr auto deflt              = constants::endianness; 
        static constexpr auto native_uint8       = is_native_big ? uint8_t{0} : uint8_t{1}; 

        static_assert(precond); //xor

        template <class T, std::enable_if_t<std::is_arithmetic_v<T>, bool> = true>
        static inline T bswap(T value) noexcept{
            
            std::array<char, sizeof(T)> src{};
            std::array<char, sizeof(T)> dst{};
            const auto idx_seq = std::make_index_sequence<sizeof(T)>();
            
            std::memcpy(src.data(), &value, sizeof(T));
            [&]<size_t ...IDX>(const std::index_sequence<IDX...>){
                ((dst[IDX] = src[sizeof(T) - IDX - 1]), ...);
            }(idx_seq);
            std::memcpy(&value, dst.data(), sizeof(T));

            return value;
        }

        template <class T, std::enable_if_t<std::is_arithmetic_v<T>, bool> = true>
        static inline void dump(void * dst, T data) noexcept{    

            if constexpr(std::endian::native != deflt){
                data = bswap(data);
            }

            std::memcpy(dst, &data, sizeof(T));
        }

        template <class T, std::enable_if_t<std::is_arithmetic_v<T>, bool> = true>
        static inline T load(const void * src) noexcept{
            
            T rs{};
            std::memcpy(&rs, src, sizeof(T));

            if constexpr(std::endian::native != deflt){
                rs = bswap(rs);
            }

            return rs;
        }
    };

    auto hash(const char * buf, size_t sz, uint32_t secret) noexcept -> hash_type{

        return dg::hasher::murmur_hash_base(buf, sz, secret);
    }

    template <class T, std::enable_if_t<std::disjunction_v<types_space::is_vector<T>, 
                                                           types_space::is_basic_string<T>>, bool> = true>
    constexpr auto get_inserter() noexcept{

        auto inserter   = []<class U, class K>(U&& container, K&& arg){
            container.push_back(std::forward<K>(arg));
        };

        return inserter;
    }

    template <class T, std::enable_if_t<std::disjunction_v<types_space::is_unordered_map<T>, 
                                                           types_space::is_unordered_set<T>, 
                                                           types_space::is_map<T>, 
                                                           types_space::is_set<T>>, bool> = true>
    constexpr auto get_inserter() noexcept{ 

        auto inserter   = []<class U, class K>(U&& container, K&& args){
            container.insert(std::forward<K>(args));
        };

        return inserter;
    }

    template <class T1, class T>
    constexpr auto safe_integer_cast(T value) noexcept -> T1{

        static_assert(std::numeric_limits<T>::is_integer);
        static_assert(std::numeric_limits<T1>::is_integer);

        if constexpr(constants::IS_SAFE_INTEGER_CONVERSION_ENABLED){
            if constexpr(std::is_unsigned_v<T> && std::is_unsigned_v<T1>){
                (void) value;
            } else if constexpr(std::is_signed_v<T> && std::is_signed_v<T1>){
                (void) value;
            } else{
                if constexpr(std::is_signed_v<T>){
                    if constexpr(sizeof(T) > sizeof(T1)){
                        (void) value;
                    } else{
                        if (value < 0){
                            std::abort();
                        } else{
                            return value; //sizeof(signed) <= sizeof(unsigned)
                        }
                    }
                } else{
                    if constexpr(sizeof(T1) > sizeof(T)){
                        (void) value;
                    } else{
                        if (value > std::numeric_limits<T1>::max()){
                            std::abort();
                        } else{
                            return value; //sizeof(unsigned) >= sizeof(signed)
                        }
                    }
                }
            }

            if (value > std::numeric_limits<T1>::max()){
                std::abort();
            }

            if (value < std::numeric_limits<T1>::min()){
                std::abort();
            }

            return value;
        } else{
            return value;
        }
    }
}

namespace dg::compact_serializer::archive{

    struct Counter{
        
        using Self = Counter;

        template <class T, std::enable_if_t<types_space::is_dg_arithmetic_v<types_space::base_type_t<T>>, bool> = true>
        auto count(T&& data) const noexcept -> size_t{
            
            return sizeof(types_space::base_type_t<T>);
        }

        template <class T, std::enable_if_t<types_space::is_unique_ptr_v<types_space::base_type_t<T>>, bool> = true>
        auto count(T&& data) const noexcept -> size_t{

            size_t rs = this->count(bool{});

            if (data){
                rs += this->count(*data);
            }

            return rs;
        }

        template <class T, std::enable_if_t<types_space::is_optional_v<types_space::base_type_t<T>>, bool> = true>
        auto count(T&& data) const noexcept -> size_t{

            size_t rs = this->count(bool{}); 

            if (data){
                rs += this->count(*data);
            }

            return rs;
        }

        template <class T, std::enable_if_t<types_space::is_tuple_v<types_space::base_type_t<T>>, bool> = true>
        auto count(T&& data) const noexcept -> size_t{

            using base_type     = types_space::base_type_t<T>;
            const auto idx_seq  = std::make_index_sequence<std::tuple_size_v<base_type>>{};
            size_t rs           = {};

            [&rs]<size_t ...IDX>(T&& data, const std::index_sequence<IDX...>) noexcept{
                rs += (Self().count(std::get<IDX>(data)) + ...);
            }(std::forward<T>(data), idx_seq);

            return rs;
        }

        template <class T, std::enable_if_t<types_space::is_noncpyable_linear_container_v<types_space::base_type_t<T>> || types_space::is_nonlinear_container_v<types_space::base_type_t<T>>, bool> = true>
        auto count(T&& data) const noexcept -> size_t{
            
            size_t rs = this->count(types::size_type{});

            for (const auto& e: data){
                rs += this->count(e);
            }

            return rs;
        }

        template <class T, std::enable_if_t<types_space::is_cpyable_linear_container_v<types_space::base_type_t<T>>, bool> = true>
        auto count(T&& data) const noexcept -> size_t{

            return this->count(types::size_type{}) + static_cast<size_t>(data.size()) * sizeof(types_space::containee_t<types_space::base_type_t<T>>);
        }

        template <class T, std::enable_if_t<types_space::is_reflectible_v<types_space::base_type_t<T>>, bool> = true>
        auto count(T&& data) const noexcept -> size_t{

            size_t rs       = {};
            auto archiver   = [&rs]<class ...Args>(Args&& ...args) noexcept{
                rs += (Self().count(std::forward<Args>(args)) + ...);
            };
            data.dg_reflect(archiver);
            
            return rs;
        }
    };

    struct Forward{

        using Self = Forward;

        template <class T, std::enable_if_t<types_space::is_dg_arithmetic_v<types_space::base_type_t<T>>, bool> = true>
        void put(char *& buf, T&& data) const noexcept{
            
            compact_serializer::utility::SyncedEndiannessService::dump(buf, std::forward<T>(data));
            std::advance(buf, sizeof(types_space::base_type_t<T>));
        }

        template <class T, std::enable_if_t<types_space::is_unique_ptr_v<types_space::base_type_t<T>>, bool> = true>
        void put(char *& buf, T&& data) const noexcept{

            this->put(buf, static_cast<bool>(data));

            if (data){
                this->put(buf, *data);
            }
        }

        template <class T, std::enable_if_t<types_space::is_optional_v<types_space::base_type_t<T>>, bool> = true>
        void put(char *& buf, T&& data) const noexcept{

            this->put(buf, static_cast<bool>(data));

            if (data){
                this->put(buf, *data);
            }
        }

        template <class T, std::enable_if_t<types_space::is_tuple_v<types_space::base_type_t<T>>, bool> = true>
        void put(char *& buf, T&& data) const noexcept{

            using base_type     = types_space::base_type_t<T>;
            const auto idx_seq  = std::make_index_sequence<std::tuple_size_v<base_type>>{};

            []<size_t ...IDX>(char *& buf, T&& data, const std::index_sequence<IDX...>) noexcept{
                (Self().put(buf, std::get<IDX>(data)), ...);
            }(buf, std::forward<T>(data), idx_seq);
        }

        template <class T, std::enable_if_t<types_space::is_noncpyable_linear_container_v<types_space::base_type_t<T>> || types_space::is_nonlinear_container_v<types_space::base_type_t<T>>, bool> = true>
        void put(char *& buf, T&& data) const noexcept{

            this->put(buf, compact_serializer::utility::safe_integer_cast<types::size_type>(data.size()));

            for (const auto& e: data){
                this->put(buf, e);
            }
        }

        template <class T, std::enable_if_t<types_space::is_cpyable_linear_container_v<types_space::base_type_t<T>>, bool> = true>
        void put(char *& buf, T&& data) const noexcept{

            using base_type = types_space::base_type_t<T>;
            using elem_type = types_space::containee_t<base_type>;

            this->put(buf, compact_serializer::utility::safe_integer_cast<types::size_type>(data.size()));

            void * dst          = buf;
            const void * src    = data.data();
            size_t cpy_sz       = data.size() * sizeof(elem_type);  

            std::memcpy(dst, src, cpy_sz);
            std::advance(buf, cpy_sz);
        }

        template <class T, std::enable_if_t<types_space::is_reflectible_v<types_space::base_type_t<T>>, bool> = true>
        void put(char *& buf, T&& data) const noexcept{

            auto archiver = [&buf]<class ...Args>(Args&& ...args) noexcept{
                (Self().put(buf, std::forward<Args>(args)), ...);
            };

            data.dg_reflect(archiver);
        }
    };

    struct Backward{

        using Self = Backward;

        template <class T, std::enable_if_t<types_space::is_dg_arithmetic_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, T&& data) const{

            using base_type = types_space::base_type_t<T>;
            data = compact_serializer::utility::SyncedEndiannessService::load<base_type>(buf);
            std::advance(buf, sizeof(base_type));
        }

        template <class T, std::enable_if_t<types_space::is_unique_ptr_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, T&& data) const{

            using containee_type = typename types_space::base_type_t<T>::element_type;
            bool status = {};
            this->put(buf, status);

            if (status){
                auto obj = containee_type{};
                this->put(buf, obj);
                data = std::make_unique<containee_type>(std::move(obj));
            } else{
                data = nullptr;
            }
        }

        template <class T, std::enable_if_t<types_space::is_optional_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, T&& data) const{

            using containee_type = typename types_space::base_type_t<T>::value_type;
            bool status = {};
            this->put(buf, status);

            if (status){
                auto obj = containee_type{};
                this->put(buf, obj);
                data = std::optional<containee_type>(std::in_place_t{}, std::move(obj));
            } else{
                data = std::nullopt;
            }
        }

        template <class T, std::enable_if_t<types_space::is_tuple_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, T&& data) const{

            using base_type     = types_space::base_type_t<T>;
            const auto idx_seq  = std::make_index_sequence<std::tuple_size_v<base_type>>{};

            []<size_t ...IDX>(const char *& buf, T&& data, const std::index_sequence<IDX...>){
                (Self().put(buf, std::get<IDX>(data)), ...);
            }(buf, std::forward<T>(data), idx_seq);
        }

        template <class T, std::enable_if_t<types_space::is_noncpyable_linear_container_v<types_space::base_type_t<T>> || types_space::is_nonlinear_container_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, T&& data) const{
            
            using base_type = types_space::base_type_t<T>;
            using elem_type = types_space::containee_t<base_type>;
            
            auto sz         = types::size_type{};
            auto isrter     = compact_serializer::utility::get_inserter<base_type>();
            this->put(buf, sz); 
            data.reserve(sz);

            for (size_t i = 0; i < sz; ++i){
                elem_type e{};
                this->put(buf, e);
                isrter(data, std::move(e));
            }
        }

        template <class T, std::enable_if_t<types_space::is_cpyable_linear_container_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, T&& data) const{

            using base_type = types_space::base_type_t<T>;
            using elem_type = types_space::containee_t<base_type>;
            
            auto sz = types::size_type{};
            this->put(buf, sz);
            data.resize(sz);

            void * dst          = data.data();
            const void * src    = buf;
            size_t cpy_sz       = sz * sizeof(elem_type); 

            std::memcpy(dst, src, cpy_sz);
            std::advance(buf, cpy_sz);
        }

        template <class T, std::enable_if_t<types_space::is_reflectible_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, T&& data) const{

            auto archiver = [&buf]<class ...Args>(Args&& ...args){
                (Self().put(buf, std::forward<Args>(args)), ...);
            };

            data.dg_reflect(archiver);
        }
    };

    struct SafeBackward{

        using Self = SafeBackward;

        template <class T, std::enable_if_t<types_space::is_dg_arithmetic_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, size_t& buf_sz, T&& data) const{

            using base_type = types_space::base_type_t<T>;

            if (buf_sz < sizeof(base_type)){
                throw dg::compact_serializer::exception_space::corrupted_format();
            }

            data    = compact_serializer::utility::SyncedEndiannessService::load<base_type>(buf);
            std::advance(buf, sizeof(base_type));
            buf_sz  -= sizeof(base_type);
        }

        template <class T, std::enable_if_t<types_space::is_unique_ptr_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, size_t& buf_sz, T&& data) const{

            using containee_type = typename types_space::base_type_t<T>::element_type;
            bool status = {};
            this->put(buf, buf_sz, status);

            if (status){
                auto obj = containee_type{};
                this->put(buf, buf_sz, obj);
                data = std::make_unique<containee_type>(std::move(obj));
            } else{
                data = nullptr;
            }
        }

        template <class T, std::enable_if_t<types_space::is_optional_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, size_t& buf_sz, T&& data) const{

            using containee_type = typename types_space::base_type_t<T>::value_type;
            bool status = {};
            this->put(buf, buf_sz, status);

            if (status){
                auto obj = containee_type{};
                this->put(buf, buf_sz, obj);
                data = std::optional<containee_type>(std::in_place_t{}, std::move(obj));
            } else{
                data = std::nullopt;
            }
        }

        template <class T, std::enable_if_t<types_space::is_tuple_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, size_t& buf_sz, T&& data) const{

            using base_type     = types_space::base_type_t<T>;
            const auto idx_seq  = std::make_index_sequence<std::tuple_size_v<base_type>>{};

            []<size_t ...IDX>(const char *& buf, size_t& buf_sz, T&& data, const std::index_sequence<IDX...>){
                (Self().put(buf, buf_sz, std::get<IDX>(data)), ...);
            }(buf, buf_sz, std::forward<T>(data), idx_seq);
        }

        template <class T, std::enable_if_t<types_space::is_noncpyable_linear_container_v<types_space::base_type_t<T>> || types_space::is_nonlinear_container_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, size_t& buf_sz, T&& data) const{

            using base_type = types_space::base_type_t<T>;
            using elem_type = types_space::containee_t<base_type>;
            
            auto sz         = types::size_type{};
            auto isrter     = compact_serializer::utility::get_inserter<base_type>();
            this->put(buf, buf_sz, sz); 
            data.reserve(sz);

            for (size_t i = 0; i < sz; ++i){
                elem_type e{};
                this->put(buf, buf_sz, e);
                isrter(data, std::move(e));
            }
        }

        template <class T, std::enable_if_t<types_space::is_cpyable_linear_container_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, size_t& buf_sz, T&& data) const{

            using base_type = types_space::base_type_t<T>;
            using elem_type = types_space::containee_t<base_type>;
            
            auto sz = types::size_type{};
            this->put(buf, buf_sz, sz);
            data.resize(sz);

            void * dst          = data.data();
            const void * src    = buf;
            size_t cpy_sz       = sz * sizeof(elem_type); 

            if (buf_sz < cpy_sz){
                throw dg::compact_serializer::exception_space::corrupted_format();
            }

            std::memcpy(dst, src, cpy_sz);
            std::advance(buf, cpy_sz);
            buf_sz -= cpy_sz;
        }

        template <class T, std::enable_if_t<types_space::is_reflectible_v<types_space::base_type_t<T>>, bool> = true>
        void put(const char *& buf, size_t& buf_sz, T&& data) const{

            auto archiver = [&buf, &buf_sz]<class ...Args>(Args&& ...args){
                (Self().put(buf, buf_sz, std::forward<Args>(args)), ...);
            };

            data.dg_reflect(archiver);
        }
    };
}

namespace dg::compact_serializer{

    template <class T>
    auto size(const T& obj) noexcept -> size_t{

        return dg::compact_serializer::archive::Counter{}.count(obj);
    }

    template <class T>
    auto serialize_into(char * buf, const T& obj) noexcept -> char *{

        dg::compact_serializer::archive::Forward{}.put(buf, obj);
        return buf;
    } 

    template <class T>
    auto deserialize_into(T& obj, const char * buf) -> const char *{

        dg::compact_serializer::archive::Backward{}.put(buf, obj);
        return buf;
    }

    template <class T>
    auto integrity_size(const T& obj) noexcept -> size_t{

        return compact_serializer::size(obj) + compact_serializer::size(types::hash_type{});
    }

    template <class T>
    auto integrity_serialize_into(char * buf, const T& obj, uint32_t secret = 0u) noexcept -> char *{ 
        
        char * first                = buf;
        char * last                 = dg::compact_serializer::serialize_into(first, obj);
        types::hash_type hashed     = compact_serializer::utility::hash(first, std::distance(first, last), secret);
        char * llast                = dg::compact_serializer::serialize_into(last, hashed);

        return llast;
    }

    template <class T>
    void integrity_deserialize_into(T& obj, const char * buf, size_t sz, uint32_t secret = 0u){

        if (sz < size(types::hash_type{})){
            throw dg::compact_serializer::exception_space::corrupted_format();
        }

        size_t content_sz           = sz - size(types::hash_type{});
        const char * first          = buf;
        const char * last           = std::next(first, content_sz);
        types::hash_type expecting  = {};
        types::hash_type reality    = compact_serializer::utility::hash(first, content_sz, secret);

        dg::compact_serializer::deserialize_into(expecting, last);

        if (expecting != reality){
            throw dg::compact_serializer::exception_space::corrupted_format();
        }

        {
            const char * iterating_ptr  = first;
            size_t deserializing_sz     = content_sz;
            dg::compact_serializer::archive::SafeBackward{}.put(iterating_ptr, deserializing_sz, obj);

            if (deserializing_sz != 0u){
                throw dg::compact_serializer::exception_space::corrupted_format();
            }
        }
    }

    template <class T>
    auto capintegrity_size(const T& obj) noexcept -> size_t{

        return dg::compact_serializer::size(uint64_t{}) + dg::compact_serializer::integrity_size(obj);
    }

    template <class T>
    auto capintegrity_serialize_into(char * buf, const T& obj, uint32_t secret = 0u) noexcept -> char *{

        char * first    = std::next(buf, dg::compact_serializer::size(uint64_t{}));
        char * last     = dg::compact_serializer::integrity_serialize_into(first, obj, secret);
        uint64_t sz     = std::distance(first, last);
        dg::compact_serializer::serialize_into(buf, sz); 

        return last;
    }

    template <class T>
    auto capintegrity_deserialize_into(T& obj, const char * buf, size_t sz, uint32_t secret = 0u) -> const char *{

        if (sz < dg::compact_serializer::size(uint64_t{})){
            throw dg::compact_serializer::exception_space::corrupted_format();
        }

        uint64_t obj_sz     = {};
        const char * first  = dg::compact_serializer::deserialize_into(obj_sz, buf);
        dg::compact_serializer::integrity_deserialize_into(obj, first, obj_sz, secret);

        return std::next(first, obj_sz);
    }

    template <class Stream, class T, std::enable_if_t<types_space::is_byte_stream_container_v<Stream>, bool> = true>
    auto serialize(const T& obj) -> Stream{
        
        Stream stream{};
        stream.resize(dg::compact_serializer::size(obj));
        dg::compact_serializer::serialize_into(stream.data(), obj);

        return stream;
    }

    template <class Stream, class T, std::enable_if_t<types_space::is_byte_stream_container_v<Stream>, bool> = true>
    auto integrity_serialize(const T& obj, uint32_t secret = 0u) -> Stream{

        Stream stream{};
        stream.resize(dg::compact_serializer::integrity_size(obj));
        dg::compact_serializer::integrity_serialize_into(stream.data(), obj, secret);
        
        return stream;
    }

    template <class T, class Stream, std::enable_if_t<types_space::is_byte_stream_container_v<Stream>, bool> = true>
    auto deserialize(const Stream& stream) -> T{

        T rs{};
        dg::compact_serializer::deserialize_into(rs, stream.data());

        return rs;
    }

    template <class T, class Stream, std::enable_if_t<types_space::is_byte_stream_container_v<Stream>, bool> = true>
    auto integrity_deserialize(const Stream& stream, uint32_t secret = 0u) -> T{

        T rs{};
        dg::compact_serializer::integrity_deserialize_into(rs, stream.data(), stream.size(), secret);

        return rs;
    }
}

#endif