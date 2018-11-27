#include "redenvelope.hpp"

void RedEnvelope::get(const uint64_t envelope_id, const account_name user, const signature &sig)
{
    auto itr = _envelopes.find(envelope_id);
    enumivo_assert(itr != _envelopes.end() && itr->envelope_id == envelope_id, "envelope not exsit!");

    auto pk = getPublicKey(itr->public_key);
    //send defer action
    enumivo::transaction txn{};
    txn.actions.emplace_back(
        enumivo::permission_level(_self, N(active)),
        _self,
        N(jump),
        std::make_tuple(envelope_id, user, sig, pk));
    txn.send(0, _self, false);
}

void RedEnvelope::transfer(const account_name from, const account_name to, const asset quantity, const std::string memo)
{
    if (from == _self || to != _self)
    {
        return;
    }

    vector<string> splits;
    SplitString(memo, splits, "|");
    uint8_t type = atoi((splits[0]).c_str());
    uint64_t envelope_id = atoi((splits[1]).c_str());
    uint8_t num = atoi((splits[2]).c_str());
    string words = splits[3];
    string public_key = splits[4];

    enumivo_assert(quantity.symbol == ENU_SYMBOL, "accept ENU only");
    enumivo_assert(quantity.is_valid(), "transfer invalid quantity");

    //enumivo_assert(quantity.amount >= 1000, "amount must > 0.1 ENU");
    //enumivo_assert(quantity.amount <= MAX, "amount must <= 2000 ENU");
    enumivo_assert(num >= 1, "red envelope numbers must >= 1");

    //auto id = _next_id();

    enumivo_assert(_envelopes.find(envelope_id) == _envelopes.end(), "envelope already exsit!");

    _envelopes.emplace(_self, [&](auto &e) {
        e.envelope_id = envelope_id;
        e.type = type;
        e.words = words;
        e.public_key = public_key;
        e.total_amount = quantity;
        e.rest_amount = asset(0, ENU_SYMBOL);
        e.total_number = num;
        e.rest_numer = num;
        e.time = now();
    });
}

void RedEnvelope::jump(const uint64_t envelope_id, const account_name user, const signature &sig, const public_key &pk)
{
    require_auth(_self);
    //send defer action
    enumivo::transaction txn{};
    txn.actions.emplace_back(
        enumivo::permission_level(_self, N(active)),
        _self,
        N(reveal),
        std::make_tuple(envelope_id, user, sig, pk));
    txn.send(0, _self, false);
}

void RedEnvelope::reveal(const uint64_t envelope_id, const account_name user, const signature &sig, const public_key &pk)
{
    auto user_name = (name{user}).to_string();
    const char *mixedChar = user_name.c_str();

    checksum256 digest;
    sha256((char *)mixedChar, user_name.length(), &digest);

    /* auto hex_public_key_str = to_hex(&pk, sizeof(pk));
    print("input public key:");
    print(hex_public_key_str.c_str());
    print("\n");

    public_key new_pk;
    recover_key(&digest, (char *)&sig, sizeof(sig), (char *)&new_pk, sizeof(new_pk));
    auto new_hex_public_key_str = to_hex(&new_pk, sizeof(new_pk));

    print("recover public key:");
    print(new_hex_public_key_str.c_str());
    print("\n"); */

    assert_recover_key(&digest, (const char *)&sig, sizeof(sig), (const char *)&pk, sizeof(pk));

    auto itr = _envelopes.find(envelope_id);
    enumivo_assert(itr != _envelopes.end() && itr->envelope_id == envelope_id, "envelope not exsit!");
    _envelopes.erase(itr);
}

void RedEnvelope::reset()
{
    require_auth(_self);
    auto i = 0;
    auto itr = _envelopes.begin();
    while (itr != _envelopes.end())
    {
        i++;
        _envelopes.erase(itr);
        itr = _envelopes.begin();
    }
    print("\nenvelope number:");
    print(i);
}