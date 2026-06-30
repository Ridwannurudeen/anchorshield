pragma circom 2.2.0;

include "components/poseidon255.circom";
include "components/merkleProof.circom";
include "comparators.circom";
include "bitify.circom";

template Boolean() {
    signal input in;

    in * (in - 1) === 0;
}

template FoldHash(n) {
    signal input in[n];
    signal output out;

    component hashers[n - 1];

    hashers[0] = Poseidon255(2);
    hashers[0].in[0] <== in[0];
    hashers[0].in[1] <== in[1];

    for (var i = 1; i < n - 1; i++) {
        hashers[i] = Poseidon255(2);
        hashers[i].in[0] <== hashers[i - 1].out;
        hashers[i].in[1] <== in[i + 1];
    }

    out <== hashers[n - 2].out;
}

template BitsLessThanBlsScalar() {
    signal input bits[255];

    var scalarBits[255] = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,0,1,1,0,1,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,0,0,0,0,0,0,0,0,1,0,0,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,0,1,0,1,0,1,0,0,0,0,0,0,0,0,1,1,0,1,1,1,0,0,0,0,1,0,1,1,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,1,0,1,1,1,0,0,1,1,1,0,0,1,1,0,0,1,1,0,0,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,0,1,0,1,1,1,0,0,1,1,0,0,1,0,1,0,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,0,1,1,0,1,1,0,1,1,1,1,1,0,0,1,1,1];

    signal eq[256];
    signal lt[256];

    eq[255] <== 1;
    lt[255] <== 0;

    for (var j = 0; j < 255; j++) {
        var i = 254 - j;
        var constantBit = scalarBits[i];

        if (constantBit == 1) {
            lt[i] <== lt[i + 1] + eq[i + 1] * (1 - bits[i]);
            eq[i] <== eq[i + 1] * bits[i];
        } else {
            eq[i + 1] * bits[i] === 0;
            lt[i] <== lt[i + 1];
            eq[i] <== eq[i + 1] * (1 - bits[i]);
        }
    }

    lt[0] === 1;
}

template Low248Hash(n) {
    signal input in[n];
    signal output out;

    component hasher = Poseidon255(n);
    hasher.in <== in;

    component bits = Num2Bits(255);
    bits.in <== hasher.out;

    component canonical = BitsLessThanBlsScalar();
    canonical.bits <== bits.out;

    var coeff = 1;
    var acc = 0;
    for (var i = 0; i < 248; i++) {
        acc += bits.out[i] * coeff;
        coeff = coeff + coeff;
    }

    out <== acc;
}

template ExclusionProof(depth) {
    signal input key;
    signal input low_value;
    signal input low_next;
    signal input low_index;
    signal input low_siblings[depth];
    signal input root;

    component keyBits = Num2Bits(248);
    keyBits.in <== key;

    component lowValueBits = Num2Bits(248);
    lowValueBits.in <== low_value;

    component lowNextBits = Num2Bits(248);
    lowNextBits.in <== low_next;

    component lowLeaf = Poseidon255(2);
    lowLeaf.in[0] <== low_value;
    lowLeaf.in[1] <== low_next;

    component rootChecker = MerkleProof(depth);
    rootChecker.leaf <== lowLeaf.out;
    rootChecker.leafIndex <== low_index;
    rootChecker.siblings <== low_siblings;
    rootChecker.out === root;

    component lowBeforeKey = LessThan(248);
    lowBeforeKey.in[0] <== low_value;
    lowBeforeKey.in[1] <== key;
    lowBeforeKey.out === 1;

    component keyBeforeNext = LessThan(248);
    keyBeforeNext.in[0] <== key;
    keyBeforeNext.in[1] <== low_next;

    component nextIsSentinel = IsZero();
    nextIsSentinel.in <== low_next;

    keyBeforeNext.out + nextIsSentinel.out === 1;
}

template Eligibility(treeDepth, denyDepth, revocationDepth) {
    signal input issuer_id;
    signal input policy_id;
    signal input kyc_required;
    signal input sanctions_required;
    signal input allowed_country;
    signal input min_age;
    signal input min_investor_type;
    signal input action_type;
    signal input asset_id;
    signal input amount;
    signal input recipient;
    signal input action_id;
    signal input epoch;
    signal input sanctions_root;
    signal input revocation_root;

    signal input user_secret;
    signal input kyc_passed;
    signal input country;
    signal input age;
    signal input investor_type;
    signal input tx_limit;
    signal input issued_at;
    signal input expires_at;
    signal input merkle_index;
    signal input merkle_siblings[treeDepth];
    signal input packet_originator;
    signal input packet_beneficiary;
    signal input packet_amount;
    signal input packet_corridor;
    signal input packet_action_id;
    signal input sanctions_low_value;
    signal input sanctions_low_next;
    signal input sanctions_low_index;
    signal input sanctions_low_siblings[denyDepth];
    signal input revocation_low_value;
    signal input revocation_low_next;
    signal input revocation_low_index;
    signal input revocation_low_siblings[revocationDepth];

    signal output credential_root;
    signal output packet_hash;
    signal output nullifier;
    signal output action_binding;

    component kycRequiredBool = Boolean();
    kycRequiredBool.in <== kyc_required;

    component sanctionsRequiredBool = Boolean();
    sanctionsRequiredBool.in <== sanctions_required;

    component kycPassedBool = Boolean();
    kycPassedBool.in <== kyc_passed;

    component amountBits = Num2Bits(128);
    amountBits.in <== amount;

    component txLimitBits = Num2Bits(128);
    txLimitBits.in <== tx_limit;

    component epochBits = Num2Bits(64);
    epochBits.in <== epoch;

    component issuedAtBits = Num2Bits(64);
    issuedAtBits.in <== issued_at;

    component expiresAtBits = Num2Bits(64);
    expiresAtBits.in <== expires_at;

    component ageBits = Num2Bits(16);
    ageBits.in <== age;

    component minAgeBits = Num2Bits(16);
    minAgeBits.in <== min_age;

    component countryBits = Num2Bits(16);
    countryBits.in <== country;

    component allowedCountryBits = Num2Bits(16);
    allowedCountryBits.in <== allowed_country;

    component investorBits = Num2Bits(16);
    investorBits.in <== investor_type;

    component minInvestorBits = Num2Bits(16);
    minInvestorBits.in <== min_investor_type;

    component actionTypeBits = Num2Bits(8);
    actionTypeBits.in <== action_type;

    kyc_required * (1 - kyc_passed) === 0;
    country === allowed_country;

    component minAgeCheck = GreaterEqThan(16);
    minAgeCheck.in[0] <== age;
    minAgeCheck.in[1] <== min_age;
    minAgeCheck.out === 1;

    component minInvestorCheck = GreaterEqThan(16);
    minInvestorCheck.in[0] <== investor_type;
    minInvestorCheck.in[1] <== min_investor_type;
    minInvestorCheck.out === 1;

    component limitCheck = LessEqThan(128);
    limitCheck.in[0] <== amount;
    limitCheck.in[1] <== tx_limit;
    limitCheck.out === 1;

    component issuedCheck = LessEqThan(64);
    issuedCheck.in[0] <== issued_at;
    issuedCheck.in[1] <== epoch;
    issuedCheck.out === 1;

    component expiryCheck = LessEqThan(64);
    expiryCheck.in[0] <== epoch;
    expiryCheck.in[1] <== expires_at;
    expiryCheck.out === 1;

    packet_amount === amount;
    packet_corridor === allowed_country;
    packet_action_id === action_id;

    component credentialHasher = FoldHash(9);
    credentialHasher.in[0] <== user_secret;
    credentialHasher.in[1] <== issuer_id;
    credentialHasher.in[2] <== kyc_passed;
    credentialHasher.in[3] <== country;
    credentialHasher.in[4] <== age;
    credentialHasher.in[5] <== investor_type;
    credentialHasher.in[6] <== tx_limit;
    credentialHasher.in[7] <== issued_at;
    credentialHasher.in[8] <== expires_at;

    component rootChecker = MerkleProof(treeDepth);
    rootChecker.leaf <== credentialHasher.out;
    rootChecker.leafIndex <== merkle_index;
    rootChecker.siblings <== merkle_siblings;
    credential_root <== rootChecker.out;

    component sanctionsKey = Low248Hash(2);
    sanctionsKey.in[0] <== user_secret;
    sanctionsKey.in[1] <== issuer_id;

    component sanctionsExclusion = ExclusionProof(denyDepth);
    sanctionsExclusion.key <== sanctionsKey.out;
    sanctionsExclusion.low_value <== sanctions_low_value;
    sanctionsExclusion.low_next <== sanctions_low_next;
    sanctionsExclusion.low_index <== sanctions_low_index;
    sanctionsExclusion.low_siblings <== sanctions_low_siblings;
    sanctionsExclusion.root <== sanctions_root;

    component revocationKey = Low248Hash(1);
    revocationKey.in[0] <== credentialHasher.out;

    component revocationExclusion = ExclusionProof(revocationDepth);
    revocationExclusion.key <== revocationKey.out;
    revocationExclusion.low_value <== revocation_low_value;
    revocationExclusion.low_next <== revocation_low_next;
    revocationExclusion.low_index <== revocation_low_index;
    revocationExclusion.low_siblings <== revocation_low_siblings;
    revocationExclusion.root <== revocation_root;

    component packetHasher = FoldHash(5);
    packetHasher.in[0] <== packet_originator;
    packetHasher.in[1] <== packet_beneficiary;
    packetHasher.in[2] <== packet_amount;
    packetHasher.in[3] <== packet_corridor;
    packetHasher.in[4] <== packet_action_id;
    packet_hash <== packetHasher.out;

    component nullifierHasher = FoldHash(3);
    nullifierHasher.in[0] <== user_secret;
    nullifierHasher.in[1] <== policy_id;
    nullifierHasher.in[2] <== epoch;
    nullifier <== nullifierHasher.out;

    component actionHasher = FoldHash(8);
    actionHasher.in[0] <== action_type;
    actionHasher.in[1] <== asset_id;
    actionHasher.in[2] <== amount;
    actionHasher.in[3] <== recipient;
    actionHasher.in[4] <== action_id;
    actionHasher.in[5] <== packetHasher.out;
    actionHasher.in[6] <== policy_id;
    actionHasher.in[7] <== epoch;
    action_binding <== actionHasher.out;
}

component main { public [
    issuer_id,
    policy_id,
    kyc_required,
    sanctions_required,
    allowed_country,
    min_age,
    min_investor_type,
    action_type,
    asset_id,
    amount,
    recipient,
    action_id,
    epoch,
    sanctions_root,
    revocation_root
] } = Eligibility(16, 20, 20);
