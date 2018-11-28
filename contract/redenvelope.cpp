#include "redenvelope.hpp"

void RedEnvelope::get(const uint64_t envelope_id, const account_name user, const signature &sig)
{
    auto itr = _envelopes.find(envelope_id);
    enumivo_assert(itr != _envelopes.end() && itr->envelope_id == envelope_id, "envelope not exsit!");

    auto pk = getPublicKey(itr->public_key);

    enumivo::transaction txn{};

    switch (itr->type)
    {
        //normal
    case 1:
        //inline action
        action(permission_level{_self, N(active)}, _self, N(reveal), std::make_tuple(envelope_id, user, sig, pk))
            .send();
        break;
    case 2:
        //send defer action
        txn.actions.emplace_back(
            enumivo::permission_level(_self, N(active)),
            _self,
            N(hop),
            std::make_tuple(envelope_id, user, sig, pk));
        txn.send(0, _self, false);
        break;

    default:
        enumivo_assert(false, "type error!");
    }
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
        e.creator = from;
        e.words = words;
        e.public_key = public_key;
        e.total_quantity = quantity;
        e.rest_quantity = quantity;
        e.total_number = num;
        e.rest_number = num;
        e.create_time = now();
        e.expire_time = now() + 24 * 60 * 60; //1day
    });
}

void RedEnvelope::hop(const uint64_t envelope_id, const account_name user, const signature &sig, const public_key &pk)
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
    require_auth(_self);

    auto itr = _envelopes.find(envelope_id);
    enumivo_assert(itr != _envelopes.end() && itr->envelope_id == envelope_id, "envelope not exsit!");

    uint64_t create_time = itr->create_time;

    auto user_name = (name{user}).to_string();
    auto raw_data = user_name + int2str(envelope_id) + int2str(create_time);
    print("\nraw_data:");
    print(raw_data);
    const char *mixedChar = raw_data.c_str();

    checksum256 digest;
    sha256((char *)mixedChar, raw_data.length(), &digest);

    auto hex_public_key_str = to_hex(&pk, sizeof(pk));
    print("input public key:");
    print(hex_public_key_str.c_str());
    print("\n");

    public_key new_pk;
    recover_key(&digest, (char *)&sig, sizeof(sig), (char *)&new_pk, sizeof(new_pk));
    auto new_hex_public_key_str = to_hex(&new_pk, sizeof(new_pk));

    print("recover public key:");
    print(new_hex_public_key_str.c_str());
    print("\n");

    assert_recover_key(&digest, (const char *)&sig, sizeof(sig), (const char *)&pk, sizeof(pk));

    /* "total_amount" : "0.1000 ENU",
                     "rest_amount" : "0.0000 ENU",
                                     "total_number" : 10,
                                     "rest_numer" : 10, */

    auto total_amount = itr->total_quantity.amount;
    auto rest_amount = itr->rest_quantity.amount;
    auto total_number = itr->total_number;
    auto rest_number = itr->rest_number;
    string creator = (name{itr->creator}).to_string();
    string words = itr->words;
    uint64_t this_amount;

    enumivo_assert(rest_amount > 0 && rest_number > 0, "this envelope is empty!");

    switch (itr->type)
    {
        //normal
    case 1:
        this_amount = total_amount / total_number;
        rest_amount = total_amount - this_amount;
        rest_number -= 1;
        break;

    default:
        enumivo_assert(false, "type error!");
    }

    string memo = "get red envelope from " + creator + "," + words;

    _envelopes.modify(itr, 0, [&](auto &e) {
        e.rest_quantity = asset(rest_amount, ENU_SYMBOL);
        e.rest_number = rest_number;
    });

    //send
    action(permission_level{_self, N(active)}, N(enu.token), N(transfer), std::make_tuple(_self, user, asset(this_amount, ENU_SYMBOL), memo))
        .send();

    //_envelopes.erase(itr);
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

void RedEnvelope::release(const uint64_t envelope_id)
{
    require_auth(_self);
}