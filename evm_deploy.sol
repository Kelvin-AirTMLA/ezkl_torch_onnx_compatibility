// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    DELTA = 4131629893567559867359510883348571134090853742863529169391034518566172092834;
    uint256 internal constant        R = 21888242871839275222246405745257275088548364400416034343698204186575808495617; 

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x31e4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x32e4;

    uint256 internal constant                VK_MPTR = 0x37c0;
    uint256 internal constant         VK_DIGEST_MPTR = 0x37c0;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x37e0;
    uint256 internal constant                 K_MPTR = 0x3800;
    uint256 internal constant             N_INV_MPTR = 0x3820;
    uint256 internal constant             OMEGA_MPTR = 0x3840;
    uint256 internal constant         OMEGA_INV_MPTR = 0x3860;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x3880;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x38a0;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x38c0;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x38e0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x3900;
    uint256 internal constant              G1_X_MPTR = 0x3920;
    uint256 internal constant              G1_Y_MPTR = 0x3940;
    uint256 internal constant            G2_X_1_MPTR = 0x3960;
    uint256 internal constant            G2_X_2_MPTR = 0x3980;
    uint256 internal constant            G2_Y_1_MPTR = 0x39a0;
    uint256 internal constant            G2_Y_2_MPTR = 0x39c0;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x39e0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x3a00;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x3a20;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x3a40;

    uint256 internal constant CHALLENGE_MPTR = 0x5f20;

    uint256 internal constant THETA_MPTR = 0x5f20;
    uint256 internal constant  BETA_MPTR = 0x5f40;
    uint256 internal constant GAMMA_MPTR = 0x5f60;
    uint256 internal constant     Y_MPTR = 0x5f80;
    uint256 internal constant     X_MPTR = 0x5fa0;
    uint256 internal constant  ZETA_MPTR = 0x5fc0;
    uint256 internal constant    NU_MPTR = 0x5fe0;
    uint256 internal constant    MU_MPTR = 0x6000;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x6020;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x6040;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x6060;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x6080;
    uint256 internal constant             X_N_MPTR = 0x60a0;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x60c0;
    uint256 internal constant          L_LAST_MPTR = 0x60e0;
    uint256 internal constant         L_BLIND_MPTR = 0x6100;
    uint256 internal constant             L_0_MPTR = 0x6120;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x6140;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x6160;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x6180;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x61a0;
    uint256 internal constant          R_EVAL_MPTR = 0x61c0;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x61e0;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x6200;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x6220;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x6240;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), R)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), R)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(R, 2))
                mstore(add(gp_mptr, 0xa0), R)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), R)
                    all_inv := mulmod(all_inv, mload(mptr), R)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), R)
                let inv_second := mulmod(all_inv, mload(first_mptr), R)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field 

            // Initialize success as true
            let success := true

            {
                // Load vk_digest and num_instances of vk into memory
                mstore(0x37c0, 0x11adf97f5bc674d872ead3b540525733a417af234461c6e54d90e46316a69b11) // vk_digest
                mstore(0x37e0, 0x000000000000000000000000000000000000000000000000000000000000031a) // num_instances

                // Check valid length of proof
                success := and(success, eq(0x6ae0, proof.length))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, instances.length))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := instances.offset
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := proof.offset
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0b40) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x1180) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x14c0) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0140) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x37a0) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Load full vk into memory
                mstore(0x37c0, 0x11adf97f5bc674d872ead3b540525733a417af234461c6e54d90e46316a69b11) // vk_digest
                mstore(0x37e0, 0x000000000000000000000000000000000000000000000000000000000000031a) // num_instances
                mstore(0x3800, 0x0000000000000000000000000000000000000000000000000000000000000011) // k
                mstore(0x3820, 0x30643640b9f82f90e83b698e5ea6179c7c05542e859533b48b9953a2f5360801) // n_inv
                mstore(0x3840, 0x304cd1e79cfa5b0f054e981a27ed7706e7ea6b06a7f266ef8db819c179c2c3ea) // omega
                mstore(0x3860, 0x193586da872cdeff023d6ab2263a131b4780db8878be3c3b7f8f019c06fcb0fb) // omega_inv
                mstore(0x3880, 0x299110e6835fd73731fb3ce6de87151988da403c265467a96b9cda0d7daa72e4) // omega_inv_to_l
                mstore(0x38a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x38c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x38e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x3900, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x3920, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x3940, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x3960, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x3980, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x39a0, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x39c0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x39e0, 0x13a90f0118a8e38d05dcc84eafe8975b56e796986116b0c07d4c0664a1ec1cf5) // neg_s_g2_x_1
                mstore(0x3a00, 0x260e91caa02369ff29b45ca008a67e0aaa288da0ee6daf4be1e21e79831df8d2) // neg_s_g2_x_2
                mstore(0x3a20, 0x0d662d31a772b97fd34b09b696980fedd4aecced1ae359f592b12dd5bd9bdd3f) // neg_s_g2_y_1
                mstore(0x3a40, 0x2e32950e6d96e2d9361bdeb71b191b4a89519f1a3915dc8230c9f072829b322a) // neg_s_g2_y_2
                mstore(0x3a60, 0x1b272f21b62cc1af4505bf6761c472c7afeb89bd33966212181c4bd8607d8bb3) // fixed_comms[0].x
                mstore(0x3a80, 0x02f398cda294d39687d96bdfd02b6cad14f19fc11bf378b92d888df4e8d44b7e) // fixed_comms[0].y
                mstore(0x3aa0, 0x17324a96abcd2d9eeb38c428d2ea80900bf4e879888a748ae00b700743e9a078) // fixed_comms[1].x
                mstore(0x3ac0, 0x0cceb9bcd44a90a325ccad4bd4266cb4174e339d36fcad9ecd4c978b71319bd1) // fixed_comms[1].y
                mstore(0x3ae0, 0x2eb983a49b88eea0264f0123721fdc284c4940f83931b105ede8138393d889ed) // fixed_comms[2].x
                mstore(0x3b00, 0x01a553d709e196aedd3342af0d78135b7df86805ab90e5199fe05d041b845c0d) // fixed_comms[2].y
                mstore(0x3b20, 0x23e7b5583bf062781091f9c50df8d827e493812c4b0003f32dcc532233c2c387) // fixed_comms[3].x
                mstore(0x3b40, 0x0ab90c99f1529ef0bb456baac1674f5f2c319ea5ac8503b5bc701ddc1bedcf1d) // fixed_comms[3].y
                mstore(0x3b60, 0x304388beb089dc4e94c7663974b6e63bf388fc4bc49b63ff521f6e0c7b225648) // fixed_comms[4].x
                mstore(0x3b80, 0x037753fbc0cab72cf86b27fca7e3026b6cd1015eaefa5a12319ee362be7911e1) // fixed_comms[4].y
                mstore(0x3ba0, 0x2dcf8b3e076838ccef7eaddcce23aa1c07b5bc14782e6ba6adaa9332fbf88419) // fixed_comms[5].x
                mstore(0x3bc0, 0x21b95cb154f01f5a1fc63102c3f6d5f66fac88077de4f8cb631f26a1e5054471) // fixed_comms[5].y
                mstore(0x3be0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[6].x
                mstore(0x3c00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[6].y
                mstore(0x3c20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[7].x
                mstore(0x3c40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[7].y
                mstore(0x3c60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[8].x
                mstore(0x3c80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[8].y
                mstore(0x3ca0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[9].x
                mstore(0x3cc0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[9].y
                mstore(0x3ce0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[10].x
                mstore(0x3d00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[10].y
                mstore(0x3d20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[11].x
                mstore(0x3d40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[11].y
                mstore(0x3d60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[12].x
                mstore(0x3d80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[12].y
                mstore(0x3da0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[13].x
                mstore(0x3dc0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[13].y
                mstore(0x3de0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[14].x
                mstore(0x3e00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[14].y
                mstore(0x3e20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[15].x
                mstore(0x3e40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[15].y
                mstore(0x3e60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[16].x
                mstore(0x3e80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[16].y
                mstore(0x3ea0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[17].x
                mstore(0x3ec0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[17].y
                mstore(0x3ee0, 0x1104dbb190e505d9afcd16218b4aeb7354ffa28d4490154b3337d3f7ba1143ea) // fixed_comms[18].x
                mstore(0x3f00, 0x11937ba2312354ea84b23c9716274d5dce48397d7cdac75b8f0803948c803d7b) // fixed_comms[18].y
                mstore(0x3f20, 0x1104dbb190e505d9afcd16218b4aeb7354ffa28d4490154b3337d3f7ba1143ea) // fixed_comms[19].x
                mstore(0x3f40, 0x11937ba2312354ea84b23c9716274d5dce48397d7cdac75b8f0803948c803d7b) // fixed_comms[19].y
                mstore(0x3f60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[20].x
                mstore(0x3f80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[20].y
                mstore(0x3fa0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[21].x
                mstore(0x3fc0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[21].y
                mstore(0x3fe0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[22].x
                mstore(0x4000, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[22].y
                mstore(0x4020, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[23].x
                mstore(0x4040, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[23].y
                mstore(0x4060, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[24].x
                mstore(0x4080, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[24].y
                mstore(0x40a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[25].x
                mstore(0x40c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[25].y
                mstore(0x40e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[26].x
                mstore(0x4100, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[26].y
                mstore(0x4120, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[27].x
                mstore(0x4140, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[27].y
                mstore(0x4160, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[28].x
                mstore(0x4180, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[28].y
                mstore(0x41a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[29].x
                mstore(0x41c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[29].y
                mstore(0x41e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[30].x
                mstore(0x4200, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[30].y
                mstore(0x4220, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[31].x
                mstore(0x4240, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[31].y
                mstore(0x4260, 0x1ac39ecb8e06b712e93ddd2e04eeb0fa7abb439d2a434bf2066926e6a297dc93) // fixed_comms[32].x
                mstore(0x4280, 0x1a03263d2af57671d13f562a0aeeb04d0353b84654d1b15b42a532644524aa50) // fixed_comms[32].y
                mstore(0x42a0, 0x20f4e3ccd2de1215f48454dba9ba9cfceed1dcf136d82fa860b81a49cc21ffbd) // fixed_comms[33].x
                mstore(0x42c0, 0x0141c7ca64a2bad0c078c0819691a0a63f88856cf3174a59f827ec0f3fa72786) // fixed_comms[33].y
                mstore(0x42e0, 0x170cf17454e0bb9a90de1280970f7e172fc6f9ca4f1731c4f37ddff0c8c09e93) // fixed_comms[34].x
                mstore(0x4300, 0x0c1cfbb1fee0d089afe349b91a19ab7834b8baa6ebaeb33c5e0add0a505d71c9) // fixed_comms[34].y
                mstore(0x4320, 0x170cf17454e0bb9a90de1280970f7e172fc6f9ca4f1731c4f37ddff0c8c09e93) // fixed_comms[35].x
                mstore(0x4340, 0x0c1cfbb1fee0d089afe349b91a19ab7834b8baa6ebaeb33c5e0add0a505d71c9) // fixed_comms[35].y
                mstore(0x4360, 0x005b25eebe8f4a611cacfba4158ec68ed5ade4fe3284142b88467042ae69e49a) // fixed_comms[36].x
                mstore(0x4380, 0x0f02842300bd701ba106fd5e0ce3a065edd283564b79838fdb6147680e197b74) // fixed_comms[36].y
                mstore(0x43a0, 0x005b25eebe8f4a611cacfba4158ec68ed5ade4fe3284142b88467042ae69e49a) // fixed_comms[37].x
                mstore(0x43c0, 0x0f02842300bd701ba106fd5e0ce3a065edd283564b79838fdb6147680e197b74) // fixed_comms[37].y
                mstore(0x43e0, 0x00942bdce720a22d5af6abf95fa9c3ea2822653c94a873f17e32cf2b793142a5) // fixed_comms[38].x
                mstore(0x4400, 0x0dd5ce31467beaea39bc53b4938ef34b9f3c0493bd5ec39f566a900c97bab818) // fixed_comms[38].y
                mstore(0x4420, 0x00942bdce720a22d5af6abf95fa9c3ea2822653c94a873f17e32cf2b793142a5) // fixed_comms[39].x
                mstore(0x4440, 0x0dd5ce31467beaea39bc53b4938ef34b9f3c0493bd5ec39f566a900c97bab818) // fixed_comms[39].y
                mstore(0x4460, 0x2ffdf28156282261511afc494d4db7581cb0ab31adf0c58e0b3b4e0f821b83a9) // fixed_comms[40].x
                mstore(0x4480, 0x0054db6921ba4e8930abf8d2b945b7cc94f5d19a07afce67c4c3112a1e1308eb) // fixed_comms[40].y
                mstore(0x44a0, 0x2ffdf28156282261511afc494d4db7581cb0ab31adf0c58e0b3b4e0f821b83a9) // fixed_comms[41].x
                mstore(0x44c0, 0x0054db6921ba4e8930abf8d2b945b7cc94f5d19a07afce67c4c3112a1e1308eb) // fixed_comms[41].y
                mstore(0x44e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[42].x
                mstore(0x4500, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[42].y
                mstore(0x4520, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[43].x
                mstore(0x4540, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[43].y
                mstore(0x4560, 0x0832020896a706aea42d0f504a5d3c763edefdc2ad9dbba55b2a4aa65296af26) // fixed_comms[44].x
                mstore(0x4580, 0x0dfe185fdaa67063d676852d96d7717c940b681199d14da85377efd099d6990b) // fixed_comms[44].y
                mstore(0x45a0, 0x0832020896a706aea42d0f504a5d3c763edefdc2ad9dbba55b2a4aa65296af26) // fixed_comms[45].x
                mstore(0x45c0, 0x0dfe185fdaa67063d676852d96d7717c940b681199d14da85377efd099d6990b) // fixed_comms[45].y
                mstore(0x45e0, 0x116a70fb28380de6ca47cd109d8aaffc630cd05ff534e745ee7aedad0ce37447) // fixed_comms[46].x
                mstore(0x4600, 0x0d46f0ba4c6534daf22edc48caa641c92de1abf0421017d97f4da90c4bc3d07f) // fixed_comms[46].y
                mstore(0x4620, 0x1888d4f4e632445f7a3787c1c435ad195141e2d558c1dc3fc05609a4c698d199) // fixed_comms[47].x
                mstore(0x4640, 0x25910f77ad45d1afb3bbca65de1472915cb1f5cb819ec1b1cdf2b5a3f7f04fd3) // fixed_comms[47].y
                mstore(0x4660, 0x24b6773d2b05d3ec7e21d48cfd29237d980e9a60cb0b282249b463e8a2998000) // fixed_comms[48].x
                mstore(0x4680, 0x16c6354189704df3a8c663740a28768a66c4d07ceffc24272ae139b0086adc7c) // fixed_comms[48].y
                mstore(0x46a0, 0x24b6773d2b05d3ec7e21d48cfd29237d980e9a60cb0b282249b463e8a2998000) // fixed_comms[49].x
                mstore(0x46c0, 0x16c6354189704df3a8c663740a28768a66c4d07ceffc24272ae139b0086adc7c) // fixed_comms[49].y
                mstore(0x46e0, 0x25807b2fbf285055001907041fdace65aee2233a48ed784b96198409e14c13cc) // fixed_comms[50].x
                mstore(0x4700, 0x2f453f0fcc0a60ed8dfbb087d4bd40ba624a3645d6c279d3c6992fb69e987dd8) // fixed_comms[50].y
                mstore(0x4720, 0x25807b2fbf285055001907041fdace65aee2233a48ed784b96198409e14c13cc) // fixed_comms[51].x
                mstore(0x4740, 0x2f453f0fcc0a60ed8dfbb087d4bd40ba624a3645d6c279d3c6992fb69e987dd8) // fixed_comms[51].y
                mstore(0x4760, 0x28b547466f967e23ca73e17fd1f927dcd6749860f370752caa7f69382e487264) // fixed_comms[52].x
                mstore(0x4780, 0x10f27d51f2fba564495c64ef3e550fbeb6fe242ef5ff00f7cade67683ef29eed) // fixed_comms[52].y
                mstore(0x47a0, 0x28b547466f967e23ca73e17fd1f927dcd6749860f370752caa7f69382e487264) // fixed_comms[53].x
                mstore(0x47c0, 0x10f27d51f2fba564495c64ef3e550fbeb6fe242ef5ff00f7cade67683ef29eed) // fixed_comms[53].y
                mstore(0x47e0, 0x0125cc9d27f405399dddb79661d0a85675b14b38a2c398edc363a1e745f8fd24) // fixed_comms[54].x
                mstore(0x4800, 0x022f1b17b13596f6fde4d80146fbea472914671f59dff3ab87f0a9b0774aa39b) // fixed_comms[54].y
                mstore(0x4820, 0x0125cc9d27f405399dddb79661d0a85675b14b38a2c398edc363a1e745f8fd24) // fixed_comms[55].x
                mstore(0x4840, 0x022f1b17b13596f6fde4d80146fbea472914671f59dff3ab87f0a9b0774aa39b) // fixed_comms[55].y
                mstore(0x4860, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[56].x
                mstore(0x4880, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[56].y
                mstore(0x48a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[57].x
                mstore(0x48c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[57].y
                mstore(0x48e0, 0x21bf3dced918d27a775646510a7fc92d4f5e496699ab9d70b72120cc2d5a9b08) // fixed_comms[58].x
                mstore(0x4900, 0x175f01b840a073ff4e984a1298e1559fea42dc611120b9011339341953887e9f) // fixed_comms[58].y
                mstore(0x4920, 0x21bf3dced918d27a775646510a7fc92d4f5e496699ab9d70b72120cc2d5a9b08) // fixed_comms[59].x
                mstore(0x4940, 0x175f01b840a073ff4e984a1298e1559fea42dc611120b9011339341953887e9f) // fixed_comms[59].y
                mstore(0x4960, 0x2e1764e7f1266445c2e4db1342cd76ff7498f36145318e383ae1ef03b63d2f54) // fixed_comms[60].x
                mstore(0x4980, 0x0d8149d51d7fb2f9f359efc84b991fb9f1cb8ff24ec3f20a7cbcdb78aaa1c93c) // fixed_comms[60].y
                mstore(0x49a0, 0x188dea01c83234850d28dbd863f8ef431486201ac914b4d946d0481b20626545) // fixed_comms[61].x
                mstore(0x49c0, 0x29514fa8c873f41f0037eb72991fc67b42624df612ade868653e65dadb7146b5) // fixed_comms[61].y
                mstore(0x49e0, 0x280bc12f9a3a8e7d43be8d7332d6a960e5d3de84973fedc53433a95ff57b8ba9) // fixed_comms[62].x
                mstore(0x4a00, 0x05dc3dcb164e649a9b4d4353cde0552ca35dcb27e2b1b5eeffdfd12afc2bf00b) // fixed_comms[62].y
                mstore(0x4a20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[63].x
                mstore(0x4a40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[63].y
                mstore(0x4a60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[64].x
                mstore(0x4a80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[64].y
                mstore(0x4aa0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[65].x
                mstore(0x4ac0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[65].y
                mstore(0x4ae0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[66].x
                mstore(0x4b00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[66].y
                mstore(0x4b20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[67].x
                mstore(0x4b40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[67].y
                mstore(0x4b60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[68].x
                mstore(0x4b80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[68].y
                mstore(0x4ba0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[69].x
                mstore(0x4bc0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[69].y
                mstore(0x4be0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[70].x
                mstore(0x4c00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[70].y
                mstore(0x4c20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[71].x
                mstore(0x4c40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[71].y
                mstore(0x4c60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[72].x
                mstore(0x4c80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[72].y
                mstore(0x4ca0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[73].x
                mstore(0x4cc0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[73].y
                mstore(0x4ce0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[74].x
                mstore(0x4d00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[74].y
                mstore(0x4d20, 0x1b155edf39666868b131b6e2fd57b4fb00199535c22e7bb5c2c1507d567833c5) // fixed_comms[75].x
                mstore(0x4d40, 0x08622a16cff7d263ed5196d25151cda1bafcd1cdf5bc82166cce3753984a6e95) // fixed_comms[75].y
                mstore(0x4d60, 0x1b155edf39666868b131b6e2fd57b4fb00199535c22e7bb5c2c1507d567833c5) // fixed_comms[76].x
                mstore(0x4d80, 0x08622a16cff7d263ed5196d25151cda1bafcd1cdf5bc82166cce3753984a6e95) // fixed_comms[76].y
                mstore(0x4da0, 0x008f7c9b333bea89ff2c5c0939020a85d0a491c2738a5c54660dc75da97edab6) // fixed_comms[77].x
                mstore(0x4dc0, 0x0cdb48c67dfba4942756fc32b080c7c4d467d88f89d093e2219a4173956f4996) // fixed_comms[77].y
                mstore(0x4de0, 0x2d6c80ca2322b085b7a20c503c9c9160d388f0abb48b081da9588bf754ebc7d8) // fixed_comms[78].x
                mstore(0x4e00, 0x134bd8a06cd1df4df18ac09a749b6cd9ad23a023d08c74e34b217124b0d685d3) // fixed_comms[78].y
                mstore(0x4e20, 0x13e5c2b19d0b6567007ec40c7bcf54ff4c15696327f6fd5fb74b5684552163c0) // fixed_comms[79].x
                mstore(0x4e40, 0x219c629b814c13cdbeed722323b5cb721e39a12e197a0e7b5f3004897ce4a389) // fixed_comms[79].y
                mstore(0x4e60, 0x1772a637282672f71e428ef9bc2510bbeb4f82ae9decd951268df401dba00c51) // fixed_comms[80].x
                mstore(0x4e80, 0x2f25a54304b1d0f5a93b55358ae0ed61cf76a74d9ea93f9b4891ccfbda0ba2dd) // fixed_comms[80].y
                mstore(0x4ea0, 0x1aa92e3e6ed01a07ee3d771769ab08bce336e5804bf0e8299f4538734c4c3101) // fixed_comms[81].x
                mstore(0x4ec0, 0x0b171a83b59c2d42c0bc805115d519775dc8ad19dcfeaca10d45ad62d676241a) // fixed_comms[81].y
                mstore(0x4ee0, 0x2d5022653802205c11940cd76b933bf42de97d36106abb596212424832291e63) // fixed_comms[82].x
                mstore(0x4f00, 0x1f8e757ff118767f687904cb964e8f692248702542f5327402b7bb438d1aec6d) // fixed_comms[82].y
                mstore(0x4f20, 0x10b7cac675cb6393db7a303397ed29502ac1ce361b168bea61742f482352fc21) // fixed_comms[83].x
                mstore(0x4f40, 0x0f00b5ad9ae06e2308ef273e205f50f92ea7e83842e4fd8a598641604d4d1882) // fixed_comms[83].y
                mstore(0x4f60, 0x09f7bca96455e54e07713fae390b27eea2ef7c86376cb33eb376183d6fbbb8b4) // fixed_comms[84].x
                mstore(0x4f80, 0x20dca2b2bc62e6f25ddeb8d2a6947811262d448cd98342085541db7e9e0073bd) // fixed_comms[84].y
                mstore(0x4fa0, 0x2be628e2edd90bef0c311136937c65c8452e9804c37b72eedec256f6922328e8) // fixed_comms[85].x
                mstore(0x4fc0, 0x0c74498beb137f08f27b3c02b0108b933e0c88098e946695a84606bfad3582ae) // fixed_comms[85].y
                mstore(0x4fe0, 0x12986f44dfaefc9224bef7f144c3c7d47a6502ea56f3b2f55f5a43096bd41059) // fixed_comms[86].x
                mstore(0x5000, 0x0bde5daac9a1980c3a29ce473b8d10a233051ef270c34cd6f1ed189507d5930c) // fixed_comms[86].y
                mstore(0x5020, 0x12986f44dfaefc9224bef7f144c3c7d47a6502ea56f3b2f55f5a43096bd41059) // fixed_comms[87].x
                mstore(0x5040, 0x0bde5daac9a1980c3a29ce473b8d10a233051ef270c34cd6f1ed189507d5930c) // fixed_comms[87].y
                mstore(0x5060, 0x1406109729e56baf65cec42178be90593a450f1682f9a7cbcc0940b30d325be7) // fixed_comms[88].x
                mstore(0x5080, 0x0eca629129bd21d211aa16171ebdf5eab166b8ac7ccf03c905a69a47e428cb82) // fixed_comms[88].y
                mstore(0x50a0, 0x06437f6823abbb69b3bc48cf8300e1c44636dcfffa8bde8597921d6a62fd7d1c) // fixed_comms[89].x
                mstore(0x50c0, 0x2af08fd23d0e1e11011f8631619be2b6b12b18cf6944fd82e218263cbe9dde66) // fixed_comms[89].y
                mstore(0x50e0, 0x174d978933cb7a94edb8e63bda8c1496ae9184c62d37cf084ddfca6a0168e4b9) // fixed_comms[90].x
                mstore(0x5100, 0x16305f32cccc23d74a3085fd791444a00b9af317bfc184c29fceb7c89c399ac6) // fixed_comms[90].y
                mstore(0x5120, 0x22f53f710b1cded0a8ea5b1d9261daadb3fb857c8707c6f675ee81965418fd05) // fixed_comms[91].x
                mstore(0x5140, 0x0fe3b5d8103f39bf6c0fdfc4edc943e78121176d99fcf17ed121fe1a9e7cc7cc) // fixed_comms[91].y
                mstore(0x5160, 0x158ed1fd10e3450d85552b1c70acefc21d4f1db380098f97212a50b4cce3c9bc) // fixed_comms[92].x
                mstore(0x5180, 0x14d82d5bf6dec8348b4ac93db6e6df4aeaa776402560d1f1943266bb43cf1d55) // fixed_comms[92].y
                mstore(0x51a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[93].x
                mstore(0x51c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[93].y
                mstore(0x51e0, 0x19bc3bab36515fd98af28657ecb2cf816f8a224a6c298c5c6fe07dcc4b151719) // fixed_comms[94].x
                mstore(0x5200, 0x04de2f1ba8b500f910281ed117e385a40c58ff62f538dba0c1cbc634853520c0) // fixed_comms[94].y
                mstore(0x5220, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[95].x
                mstore(0x5240, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[95].y
                mstore(0x5260, 0x045522e0207ef0d62b850e88753c4a7aada7484fea4b9d4d5b3464580c8c5793) // fixed_comms[96].x
                mstore(0x5280, 0x156bdd36ff4efe0fd42c1967b9c781882819070bd9e0c6f3b2a2a6c6c8350f48) // fixed_comms[96].y
                mstore(0x52a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[97].x
                mstore(0x52c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[97].y
                mstore(0x52e0, 0x10e5c4b932f1d5bd0d3fafa5c78130cd544effbcfeae9cc215b6e0983fb31293) // fixed_comms[98].x
                mstore(0x5300, 0x277f297437908c65e58561481b551545b60104cbacbbd6c0e0fe0bc4ca08b510) // fixed_comms[98].y
                mstore(0x5320, 0x082f774562d21607c6a5c0a431a66cb8c0e69669c8ff437b8f811e6a358dc0a3) // fixed_comms[99].x
                mstore(0x5340, 0x1e395b566105c6c065075af9d6e408e0fac6d96a7b67c98b69e13597d4e2e37d) // fixed_comms[99].y
                mstore(0x5360, 0x00131d54da952b9d06f2ddea490753dda53a12bba04b0fcf54796b7126f7b744) // permutation_comms[0].x
                mstore(0x5380, 0x087dedffb9d995d3995d52bc71d1b70d7abcd0c77f24e63f379ad6f63c49c604) // permutation_comms[0].y
                mstore(0x53a0, 0x1fbee53ae90b0810416228024f6cf4001a1e42e0e9c3a403180c80a6a627bf5d) // permutation_comms[1].x
                mstore(0x53c0, 0x232ab41aed10b6db41703931c69d4412183baf65279afdf5f90707a2e4d415fe) // permutation_comms[1].y
                mstore(0x53e0, 0x115e19f62498c259c6c42e215282de8f2e8eefe98777060c24e148065da4859a) // permutation_comms[2].x
                mstore(0x5400, 0x1bd9be3764c6440e84ade59d95d0f978c5f4bc22e716f78dbdbc045adce7aa47) // permutation_comms[2].y
                mstore(0x5420, 0x10dfeb9fae1f66eb4732c22e0cb52f9757924347241463d0214b1937de6dd363) // permutation_comms[3].x
                mstore(0x5440, 0x29d25217edcf21ca8569b9bfa605b2e2b7d1edc79b1e45e1055b213aa2fbefa9) // permutation_comms[3].y
                mstore(0x5460, 0x274a57506a95bccfdab83bfc391bba1d9fe59276ed264f5794b90a956a0aeabb) // permutation_comms[4].x
                mstore(0x5480, 0x1710647633f6044aecea98820a508ba186e9bfa1148d8641e0d3a5053e82c345) // permutation_comms[4].y
                mstore(0x54a0, 0x1a2e1225342a1baf23f50550edb8de037e05ed4289310e17bcfbd88de9851a42) // permutation_comms[5].x
                mstore(0x54c0, 0x1d03859d439b34515e96f12dfcaf1678dfe3756c2cc8f425fd9055ef7fc65b14) // permutation_comms[5].y
                mstore(0x54e0, 0x23220cb5ac33b57c3a54a88f2b11e0e1972e586ec3b400a0a2b25c5fc5961dba) // permutation_comms[6].x
                mstore(0x5500, 0x20c72cac3a1345767d299573bda1b6877aa92f54fcb5c352417fdb58fdea645f) // permutation_comms[6].y
                mstore(0x5520, 0x252fc8b1ccea26b2b6213fada3d30e7f27f6ab6ee22a18e587d43dc8d0e31750) // permutation_comms[7].x
                mstore(0x5540, 0x100ee8555a96e6f1bf4218a35c9400c58b025569f310f1ca5a63400c1421e3b6) // permutation_comms[7].y
                mstore(0x5560, 0x1e4386bdd6922a5ae7f1d9624b54146a511bacf135300e6b407c81d242d2c089) // permutation_comms[8].x
                mstore(0x5580, 0x0e601af529d52d2ceb2d175c2dbf5fe807f13a0ba408e17e58f152c6c0883e7b) // permutation_comms[8].y
                mstore(0x55a0, 0x0f64f3b7a051ef6c69d8fe6c2fbbb1dfa4b4d66703a00fb71e408ac7b95459e3) // permutation_comms[9].x
                mstore(0x55c0, 0x28101b9b77c5a45b3e31cb12aa7695a3da8c61da2afb822fd6a80b003113488f) // permutation_comms[9].y
                mstore(0x55e0, 0x1149cc96dcc69b647e9608a2155feae643b01c3e427ceef2bff75d2a40c22948) // permutation_comms[10].x
                mstore(0x5600, 0x2d92b51f950ab8c043543d12df73566a9c952c184bbf3a96502ce75e655c4b19) // permutation_comms[10].y
                mstore(0x5620, 0x24afc4b0026170901dd6f112d3c2d7720418177cf1d231f79adddcf9b6ae5a16) // permutation_comms[11].x
                mstore(0x5640, 0x0646ad71ac0b6766e501d1187610b5cb6afca25d052289a066610cf58fab5cfa) // permutation_comms[11].y
                mstore(0x5660, 0x1011d4ebef6d8d0bd50b25a017bb350338b59816b0716299a09f680bfb08c66a) // permutation_comms[12].x
                mstore(0x5680, 0x033eec859125ceca74bd7bb4db11947bdab21de6a071f75d8abfe5895cb1a8a6) // permutation_comms[12].y
                mstore(0x56a0, 0x176e5b78ceb82734dff1108cdf17e74bed5e5d709185aac06c73c0fb53bbb152) // permutation_comms[13].x
                mstore(0x56c0, 0x0748270e6631836fd071a57eceee1df9f542f7d4025d1a5b460944c42d2b110e) // permutation_comms[13].y
                mstore(0x56e0, 0x1cb7e7fc664973b9e8f14848fe6cddcada951ec00b8e59df5876a27b47c7392a) // permutation_comms[14].x
                mstore(0x5700, 0x19d161a2bb72659b1800b3f5f798621df2fc563c09602d7be305f3ae1e282ebf) // permutation_comms[14].y
                mstore(0x5720, 0x085bb4a3f9726982171ec8f7b356f49a886798fb602d60628a523cfbcad9851c) // permutation_comms[15].x
                mstore(0x5740, 0x21705320bd4f08c3d9417273958b913bbe89f76ae223c443e350fbd3559f2b12) // permutation_comms[15].y
                mstore(0x5760, 0x24f109fee712fd5476b41ee315b2fb19adae778ab879fcb0ddce8881fe99d8e8) // permutation_comms[16].x
                mstore(0x5780, 0x2775956e83f82c087569ed9d69dcf5bb41f11bd338342138bfd781e3a73f36fc) // permutation_comms[16].y
                mstore(0x57a0, 0x0538f1710c26a857acaec58c317f1ba9393c796afd9cbd53a445eb6c9c813d07) // permutation_comms[17].x
                mstore(0x57c0, 0x121c039a7498c7beb3751dfec46ac00d923f6b081ccfd4a50cdb99a5c1e35a48) // permutation_comms[17].y
                mstore(0x57e0, 0x23b014d245624b7455f4a29638bc89bfccd8cb7ea48b5cbd31c1c082825996d5) // permutation_comms[18].x
                mstore(0x5800, 0x06f62fc26af969e560cc2c1bedc183bc79a14a30d53e1442738d6970772e0642) // permutation_comms[18].y
                mstore(0x5820, 0x2c038569babbba3e14d49f60b3582e9fab579a9c5f6f09a296907d9589000e04) // permutation_comms[19].x
                mstore(0x5840, 0x2adbec31a516a809402991f27adbf2c0c226afc377d12723ac7b97a1b44e264a) // permutation_comms[19].y
                mstore(0x5860, 0x26fa81a38d2c7c930e29fc63f6e8e100683df0bb7fe90613d5f1aac04b2a6513) // permutation_comms[20].x
                mstore(0x5880, 0x2e16922763414b303396e880015aec3a3ac1ddf736986033e930ca43339bb57a) // permutation_comms[20].y
                mstore(0x58a0, 0x2ff4c5e504503854aed5ac3b5e5d0ad236c879e8cbd51eee7f1acc862ef8e5cf) // permutation_comms[21].x
                mstore(0x58c0, 0x08ab1c43a8acc34ddb750d05786abd96b1c604a5aad2b9315ec3ba57fa70fa53) // permutation_comms[21].y
                mstore(0x58e0, 0x0c5b765b40fe772c5b5e13acbea389b7edd0e8da39223244242e8d86dd73e3ab) // permutation_comms[22].x
                mstore(0x5900, 0x2d587918ff1b539c4d28cc2212e7776c5c021234b665603ea32bc32fa4c86bf7) // permutation_comms[22].y
                mstore(0x5920, 0x141ce12f7cb44c5cf7666ca1327354290a75376bf156ec62f8809cd3accc5850) // permutation_comms[23].x
                mstore(0x5940, 0x251342ca1a38b903b9bafeed6026099e91264f7db885249a5eed63632d870014) // permutation_comms[23].y
                mstore(0x5960, 0x106bdfc4956bc9e6b4c9e39ab90a112eb7e0c6dad5bd4d3c3249157f34fc684a) // permutation_comms[24].x
                mstore(0x5980, 0x2b8f86988d673b7c7eec81720f8932adfcc581d968b45adc08c91517f3be1911) // permutation_comms[24].y
                mstore(0x59a0, 0x173bd19a1f214e33f2aa6c236a26c67f3162f34156212a644542e7ff73988702) // permutation_comms[25].x
                mstore(0x59c0, 0x064be0425f0ee31fe84be5c370f85299247ace43f10e7268f427e983c3785d62) // permutation_comms[25].y
                mstore(0x59e0, 0x23b7a77e240aae78288484b2d4696bd56cb2f7feb3c7b442796df19677e33b2f) // permutation_comms[26].x
                mstore(0x5a00, 0x0ccd717cb745f4fb4b6b296888c6690b91a0971702d0563e812e1e103e77c1c2) // permutation_comms[26].y
                mstore(0x5a20, 0x2570fda0496423e18b9d509496c0f0f343fe89a2cf63d17914e2c035823cb5d3) // permutation_comms[27].x
                mstore(0x5a40, 0x245fcbbf3a0dee0ce26e33f64236684d8d82eb8755b4e1fe2b0ca19411892311) // permutation_comms[27].y
                mstore(0x5a60, 0x0403998bdc019e704194317cfd52ee26f014272a923b6483de7070713d6cfbc4) // permutation_comms[28].x
                mstore(0x5a80, 0x0576100079371110de1c1c3949678b5c570c473d5ee9ba14449cc30333626a17) // permutation_comms[28].y
                mstore(0x5aa0, 0x1941771bd9e7f2d39a8254638b99c9af5bfa2b89c4746691fc81c5512ecbe636) // permutation_comms[29].x
                mstore(0x5ac0, 0x0ae99540c49c14fe805d3966f600d969858b99cd008acf1eb0e8ac39ccca5f9e) // permutation_comms[29].y
                mstore(0x5ae0, 0x28b15e18c48ad8c8c8990c7aa606812818039e08c9f5b2e44f838fe3043eb3fc) // permutation_comms[30].x
                mstore(0x5b00, 0x2ae8f9262944db72009863ed3581e87e482ce6cf4bacc420893fc726fbab425b) // permutation_comms[30].y
                mstore(0x5b20, 0x029b53a419e9aff4cc0d4b536936358fd495017f264297e2d7cfa695333a6b3a) // permutation_comms[31].x
                mstore(0x5b40, 0x1fe7c02142f7555b8a744d03aceecf593f0e04f6bd9fe1ca211c9a2a3be9d734) // permutation_comms[31].y
                mstore(0x5b60, 0x06d6f0ea532b166cf4ecfe5150f02a35448ff733d4576a29e83cdfe0608474ab) // permutation_comms[32].x
                mstore(0x5b80, 0x03140386991b6b098552615873814f3f03930b35d896a4412f8d59d42280071e) // permutation_comms[32].y
                mstore(0x5ba0, 0x30267a2587bf9a57b907e9cc460bc21520fb5c638a22e26c563b0ea2b1dd157e) // permutation_comms[33].x
                mstore(0x5bc0, 0x0ab6d70b3d027610317062a73cbe8d06c6c6ff4c4e634e1985667d32c03b2283) // permutation_comms[33].y
                mstore(0x5be0, 0x107f53a0106f5da45860adc69f8dcc26830f28bf7a369b7ae08ef3708caaa636) // permutation_comms[34].x
                mstore(0x5c00, 0x11dbaa624786e3532b0db69bcb1fdeb2263be36a70922b8878d3fb42bb61fa49) // permutation_comms[34].y
                mstore(0x5c20, 0x1a8da9cb7de1b7a92d4fe124e9b99ab1a88544c699f14115e93d8aaacb3eaa94) // permutation_comms[35].x
                mstore(0x5c40, 0x017743bbab679f004510abc8686d0d9a7e4f608faab6ac49152816c0073df89e) // permutation_comms[35].y
                mstore(0x5c60, 0x1f6a40eedf3e253d5f1cd66d3c3b0d87bc27605053cc1689fe0a9da3d8ce5a7f) // permutation_comms[36].x
                mstore(0x5c80, 0x24cbfe8795efe7545be96b518828ad3ceda032903345c3be48c81d37e117d164) // permutation_comms[36].y
                mstore(0x5ca0, 0x1dd3948f327ca66171416b45bbc4fa31a3da57b903efa3991227e34dd10994f0) // permutation_comms[37].x
                mstore(0x5cc0, 0x1b34d8a2467db5a4db7aa354d5f964dd9edf5085329e7d10f065134bdbfb1813) // permutation_comms[37].y
                mstore(0x5ce0, 0x04c556cea784981b84c730e6c94f24c6b267cd38d275168b8598e6e7703f0190) // permutation_comms[38].x
                mstore(0x5d00, 0x167849db6182885223953bc43e2b56002d363f837bdc4f542b24edc464d63f34) // permutation_comms[38].y
                mstore(0x5d20, 0x0e2eb93c1205e8c0449da1e651d09621517104c1a5f447c9cf90710579777cb4) // permutation_comms[39].x
                mstore(0x5d40, 0x2f11578d327ad57476f6df27cecd7d52e675098c7cdd6af4bb950909efec26a8) // permutation_comms[39].y
                mstore(0x5d60, 0x1fd0a36a1f273fd61ccfbf4465c1d55737c575669029c9287c3dcfe2af778fdd) // permutation_comms[40].x
                mstore(0x5d80, 0x2951b37c7bbc5990cbf0c582e044736d0262f282c4fc555b3762b41422245cd4) // permutation_comms[40].y
                mstore(0x5da0, 0x237dd95e69d612c193deee163651efd4647d6c89bfb84dbcab7ecd89bd95cd9c) // permutation_comms[41].x
                mstore(0x5dc0, 0x2265776cabf62b165c95ca871d5b15cbce17a73deb51c527bc95b6b33a19dd0b) // permutation_comms[41].y
                mstore(0x5de0, 0x26883c930ca964b45d20f0e20de67fada76f1efc3cd59b3b37238c55fb1f7977) // permutation_comms[42].x
                mstore(0x5e00, 0x24c4cef562a5b0cad524e6f56f72ab07bab305339326b4f5bfc0e4a76c81488d) // permutation_comms[42].y
                mstore(0x5e20, 0x22c276b910bfe3343ddbb53e9cd992a7cdcb12a3c4a257b5b5c30b2258594288) // permutation_comms[43].x
                mstore(0x5e40, 0x22fd595c8f52c3dc05a6f323b2ce0be5149c10608fa4f42a4966320adccd6268) // permutation_comms[43].y
                mstore(0x5e60, 0x002cb059c1d0e98e9b3ef471c1cdc734d54803c86acb38f777e2239355441692) // permutation_comms[44].x
                mstore(0x5e80, 0x21821985bcd9cf5edd044fc66e95a65a7d3773fb3839618e22bef97b4d6258e2) // permutation_comms[44].y
                mstore(0x5ea0, 0x2d02e8ca960efcf418965283a47dda1f9371b6edfe43ab1db4dbb5de1273f8f3) // permutation_comms[45].x
                mstore(0x5ec0, 0x0d7442e98386cd50004addab77844151c768d0b2e2bef2f8dac7d4dbd72c68c5) // permutation_comms[45].y
                mstore(0x5ee0, 0x132227a4929149551b754c26c8db49d7ea3a6ece830711f4ca2cc35afc6857ed) // permutation_comms[46].x
                mstore(0x5f00, 0x23d3c68c5bb9fc7a2dbe6b879f9fa01baac4effe51675c3cb71716dddaa7f047) // permutation_comms[46].y

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(instances.offset, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20))

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := instances.offset
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let y := mload(Y_MPTR)
                {
                    let f_77 := calldataload(0x4344)
                    let var0 := 0x2
                    let var1 := sub(R, f_77)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_77, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_28 := calldataload(0x36a4)
                    let a_0 := calldataload(0x3324)
                    let a_14 := calldataload(0x34e4)
                    let var10 := addmod(a_0, a_14, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_28, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := var13
                }
                {
                    let f_77 := calldataload(0x4344)
                    let var0 := 0x1
                    let var1 := sub(R, f_77)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_77, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_29 := calldataload(0x36c4)
                    let a_1 := calldataload(0x3344)
                    let a_15 := calldataload(0x3504)
                    let var10 := addmod(a_1, a_15, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_29, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_78 := calldataload(0x4364)
                    let var0 := 0x1
                    let var1 := sub(R, f_78)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_78, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_30 := calldataload(0x36e4)
                    let a_2 := calldataload(0x3364)
                    let a_16 := calldataload(0x3524)
                    let var10 := addmod(a_2, a_16, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_30, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_79 := calldataload(0x4384)
                    let var0 := 0x1
                    let var1 := sub(R, f_79)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_79, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_31 := calldataload(0x3704)
                    let a_3 := calldataload(0x3384)
                    let a_17 := calldataload(0x3544)
                    let var10 := addmod(a_3, a_17, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_31, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_79 := calldataload(0x4384)
                    let var0 := 0x1
                    let var1 := sub(R, f_79)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_79, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_32 := calldataload(0x3724)
                    let a_4 := calldataload(0x33a4)
                    let a_18 := calldataload(0x3564)
                    let var10 := addmod(a_4, a_18, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_32, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_80 := calldataload(0x43a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_80)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_80, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_33 := calldataload(0x3744)
                    let a_5 := calldataload(0x33c4)
                    let a_19 := calldataload(0x3584)
                    let var10 := addmod(a_5, a_19, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_33, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_80 := calldataload(0x43a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_80)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_80, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_34 := calldataload(0x3764)
                    let a_6 := calldataload(0x33e4)
                    let a_20 := calldataload(0x35a4)
                    let var10 := addmod(a_6, a_20, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_34, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_81 := calldataload(0x43c4)
                    let var0 := 0x1
                    let var1 := sub(R, f_81)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_81, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_35 := calldataload(0x3784)
                    let a_7 := calldataload(0x3404)
                    let a_21 := calldataload(0x35c4)
                    let var10 := addmod(a_7, a_21, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_35, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_81 := calldataload(0x43c4)
                    let var0 := 0x1
                    let var1 := sub(R, f_81)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_81, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_36 := calldataload(0x37a4)
                    let a_8 := calldataload(0x3424)
                    let a_22 := calldataload(0x35e4)
                    let var10 := addmod(a_8, a_22, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_36, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_83 := calldataload(0x4404)
                    let var0 := 0x1
                    let var1 := sub(R, f_83)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_83, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_37 := calldataload(0x37c4)
                    let a_9 := calldataload(0x3444)
                    let a_23 := calldataload(0x3604)
                    let var10 := addmod(a_9, a_23, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_37, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_83 := calldataload(0x4404)
                    let var0 := 0x1
                    let var1 := sub(R, f_83)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_83, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_38 := calldataload(0x37e4)
                    let a_10 := calldataload(0x3464)
                    let a_24 := calldataload(0x3624)
                    let var10 := addmod(a_10, a_24, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_38, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_84 := calldataload(0x4424)
                    let var0 := 0x1
                    let var1 := sub(R, f_84)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_84, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_39 := calldataload(0x3804)
                    let a_11 := calldataload(0x3484)
                    let a_25 := calldataload(0x3644)
                    let var10 := addmod(a_11, a_25, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_39, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_84 := calldataload(0x4424)
                    let var0 := 0x1
                    let var1 := sub(R, f_84)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_84, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_40 := calldataload(0x3824)
                    let a_12 := calldataload(0x34a4)
                    let a_26 := calldataload(0x3664)
                    let var10 := addmod(a_12, a_26, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_40, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_88 := calldataload(0x44a4)
                    let var0 := 0x2
                    let var1 := sub(R, f_88)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_88, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_41 := calldataload(0x3844)
                    let a_13 := calldataload(0x34c4)
                    let a_27 := calldataload(0x3684)
                    let var10 := addmod(a_13, a_27, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_41, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_77 := calldataload(0x4344)
                    let var0 := 0x1
                    let var1 := sub(R, f_77)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_77, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_28 := calldataload(0x36a4)
                    let a_0 := calldataload(0x3324)
                    let a_14 := calldataload(0x34e4)
                    let var10 := mulmod(a_0, a_14, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_28, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_78 := calldataload(0x4364)
                    let var0 := 0x1
                    let var1 := sub(R, f_78)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_78, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_29 := calldataload(0x36c4)
                    let a_1 := calldataload(0x3344)
                    let a_15 := calldataload(0x3504)
                    let var10 := mulmod(a_1, a_15, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_29, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_79 := calldataload(0x4384)
                    let var0 := 0x2
                    let var1 := sub(R, f_79)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_79, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_30 := calldataload(0x36e4)
                    let a_2 := calldataload(0x3364)
                    let a_16 := calldataload(0x3524)
                    let var10 := mulmod(a_2, a_16, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_30, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_80 := calldataload(0x43a4)
                    let var0 := 0x2
                    let var1 := sub(R, f_80)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_80, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_31 := calldataload(0x3704)
                    let a_3 := calldataload(0x3384)
                    let a_17 := calldataload(0x3544)
                    let var10 := mulmod(a_3, a_17, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_31, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_81 := calldataload(0x43c4)
                    let var0 := 0x1
                    let var1 := sub(R, f_81)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_81, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_32 := calldataload(0x3724)
                    let a_4 := calldataload(0x33a4)
                    let a_18 := calldataload(0x3564)
                    let var10 := mulmod(a_4, a_18, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_32, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_82 := calldataload(0x43e4)
                    let var0 := 0x1
                    let var1 := sub(R, f_82)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_82, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_33 := calldataload(0x3744)
                    let a_5 := calldataload(0x33c4)
                    let a_19 := calldataload(0x3584)
                    let var10 := mulmod(a_5, a_19, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_33, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_83 := calldataload(0x4404)
                    let var0 := 0x2
                    let var1 := sub(R, f_83)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_83, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_34 := calldataload(0x3764)
                    let a_6 := calldataload(0x33e4)
                    let a_20 := calldataload(0x35a4)
                    let var10 := mulmod(a_6, a_20, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_34, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_84 := calldataload(0x4424)
                    let var0 := 0x2
                    let var1 := sub(R, f_84)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_84, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_35 := calldataload(0x3784)
                    let a_7 := calldataload(0x3404)
                    let a_21 := calldataload(0x35c4)
                    let var10 := mulmod(a_7, a_21, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_35, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_82 := calldataload(0x43e4)
                    let var0 := 0x1
                    let var1 := sub(R, f_82)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_82, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_36 := calldataload(0x37a4)
                    let a_8 := calldataload(0x3424)
                    let a_22 := calldataload(0x35e4)
                    let var10 := mulmod(a_8, a_22, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_36, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_85 := calldataload(0x4444)
                    let var0 := 0x1
                    let var1 := sub(R, f_85)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_85, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_37 := calldataload(0x37c4)
                    let a_9 := calldataload(0x3444)
                    let a_23 := calldataload(0x3604)
                    let var10 := mulmod(a_9, a_23, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_37, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_86 := calldataload(0x4464)
                    let var0 := 0x1
                    let var1 := sub(R, f_86)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_86, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_38 := calldataload(0x37e4)
                    let a_10 := calldataload(0x3464)
                    let a_24 := calldataload(0x3624)
                    let var7 := mulmod(a_10, a_24, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_38, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_87 := calldataload(0x4484)
                    let var0 := 0x1
                    let var1 := sub(R, f_87)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_87, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_39 := calldataload(0x3804)
                    let a_11 := calldataload(0x3484)
                    let a_25 := calldataload(0x3644)
                    let var10 := mulmod(a_11, a_25, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_39, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_85 := calldataload(0x4444)
                    let var0 := 0x1
                    let var1 := sub(R, f_85)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_85, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_40 := calldataload(0x3824)
                    let a_12 := calldataload(0x34a4)
                    let a_26 := calldataload(0x3664)
                    let var10 := mulmod(a_12, a_26, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_40, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_88 := calldataload(0x44a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_88)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_88, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_41 := calldataload(0x3844)
                    let a_13 := calldataload(0x34c4)
                    let a_27 := calldataload(0x3684)
                    let var10 := mulmod(a_13, a_27, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_41, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_77 := calldataload(0x4344)
                    let var0 := 0x1
                    let var1 := sub(R, f_77)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_77, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_28 := calldataload(0x36a4)
                    let a_0 := calldataload(0x3324)
                    let a_14 := calldataload(0x34e4)
                    let var10 := sub(R, a_14)
                    let var11 := addmod(a_0, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_28, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_78 := calldataload(0x4364)
                    let var0 := 0x2
                    let var1 := sub(R, f_78)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_78, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_29 := calldataload(0x36c4)
                    let a_1 := calldataload(0x3344)
                    let a_15 := calldataload(0x3504)
                    let var10 := sub(R, a_15)
                    let var11 := addmod(a_1, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_29, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_78 := calldataload(0x4364)
                    let var0 := 0x1
                    let var1 := sub(R, f_78)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_78, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_30 := calldataload(0x36e4)
                    let a_2 := calldataload(0x3364)
                    let a_16 := calldataload(0x3524)
                    let var10 := sub(R, a_16)
                    let var11 := addmod(a_2, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_30, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_79 := calldataload(0x4384)
                    let var0 := 0x1
                    let var1 := sub(R, f_79)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_79, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_31 := calldataload(0x3704)
                    let a_3 := calldataload(0x3384)
                    let a_17 := calldataload(0x3544)
                    let var10 := sub(R, a_17)
                    let var11 := addmod(a_3, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_31, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_81 := calldataload(0x43c4)
                    let var0 := 0x2
                    let var1 := sub(R, f_81)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_81, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_32 := calldataload(0x3724)
                    let a_4 := calldataload(0x33a4)
                    let a_18 := calldataload(0x3564)
                    let var10 := sub(R, a_18)
                    let var11 := addmod(a_4, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_32, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_82 := calldataload(0x43e4)
                    let var0 := 0x2
                    let var1 := sub(R, f_82)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_82, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_33 := calldataload(0x3744)
                    let a_5 := calldataload(0x33c4)
                    let a_19 := calldataload(0x3584)
                    let var10 := sub(R, a_19)
                    let var11 := addmod(a_5, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_33, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_80 := calldataload(0x43a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_80)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_80, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_34 := calldataload(0x3764)
                    let a_6 := calldataload(0x33e4)
                    let a_20 := calldataload(0x35a4)
                    let var10 := sub(R, a_20)
                    let var11 := addmod(a_6, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_34, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_83 := calldataload(0x4404)
                    let var0 := 0x1
                    let var1 := sub(R, f_83)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_83, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_35 := calldataload(0x3784)
                    let a_7 := calldataload(0x3404)
                    let a_21 := calldataload(0x35c4)
                    let var10 := sub(R, a_21)
                    let var11 := addmod(a_7, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_35, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_82 := calldataload(0x43e4)
                    let var0 := 0x1
                    let var1 := sub(R, f_82)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_82, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_36 := calldataload(0x37a4)
                    let a_8 := calldataload(0x3424)
                    let a_22 := calldataload(0x35e4)
                    let var10 := sub(R, a_22)
                    let var11 := addmod(a_8, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_36, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_85 := calldataload(0x4444)
                    let var0 := 0x2
                    let var1 := sub(R, f_85)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_85, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_37 := calldataload(0x37c4)
                    let a_9 := calldataload(0x3444)
                    let a_23 := calldataload(0x3604)
                    let var10 := sub(R, a_23)
                    let var11 := addmod(a_9, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_37, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_86 := calldataload(0x4464)
                    let var0 := 0x2
                    let var1 := sub(R, f_86)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_86, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_38 := calldataload(0x37e4)
                    let a_10 := calldataload(0x3464)
                    let a_24 := calldataload(0x3624)
                    let var7 := sub(R, a_24)
                    let var8 := addmod(a_10, var7, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_38, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_87 := calldataload(0x4484)
                    let var0 := 0x2
                    let var1 := sub(R, f_87)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_87, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_39 := calldataload(0x3804)
                    let a_11 := calldataload(0x3484)
                    let a_25 := calldataload(0x3644)
                    let var10 := sub(R, a_25)
                    let var11 := addmod(a_11, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_39, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_84 := calldataload(0x4424)
                    let var0 := 0x1
                    let var1 := sub(R, f_84)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_84, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_40 := calldataload(0x3824)
                    let a_12 := calldataload(0x34a4)
                    let a_26 := calldataload(0x3664)
                    let var10 := sub(R, a_26)
                    let var11 := addmod(a_12, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_40, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_88 := calldataload(0x44a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_88)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_88, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_41 := calldataload(0x3844)
                    let a_13 := calldataload(0x34c4)
                    let a_27 := calldataload(0x3684)
                    let var10 := sub(R, a_27)
                    let var11 := addmod(a_13, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_41, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_89 := calldataload(0x44c4)
                    let var0 := 0x1
                    let var1 := sub(R, f_89)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_89, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_28 := calldataload(0x36a4)
                    let a_28_prev_1 := calldataload(0x38c4)
                    let var7 := 0x0
                    let a_0 := calldataload(0x3324)
                    let a_14 := calldataload(0x34e4)
                    let var8 := mulmod(a_0, a_14, R)
                    let var9 := addmod(var7, var8, R)
                    let a_1 := calldataload(0x3344)
                    let a_15 := calldataload(0x3504)
                    let var10 := mulmod(a_1, a_15, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := addmod(a_28_prev_1, var11, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_28, var13, R)
                    let var15 := mulmod(var6, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_90 := calldataload(0x44e4)
                    let var0 := 0x2
                    let var1 := sub(R, f_90)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_90, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_30 := calldataload(0x36e4)
                    let a_30_prev_1 := calldataload(0x38e4)
                    let var10 := 0x0
                    let a_2 := calldataload(0x3364)
                    let a_16 := calldataload(0x3524)
                    let var11 := mulmod(a_2, a_16, R)
                    let var12 := addmod(var10, var11, R)
                    let a_3 := calldataload(0x3384)
                    let a_17 := calldataload(0x3544)
                    let var13 := mulmod(a_3, a_17, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := addmod(a_30_prev_1, var14, R)
                    let var16 := sub(R, var15)
                    let var17 := addmod(a_30, var16, R)
                    let var18 := mulmod(var9, var17, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var18, r)
                }
                {
                    let f_91 := calldataload(0x4504)
                    let var0 := 0x1
                    let var1 := sub(R, f_91)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_91, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_32 := calldataload(0x3724)
                    let a_32_prev_1 := calldataload(0x3904)
                    let var7 := 0x0
                    let a_4 := calldataload(0x33a4)
                    let a_18 := calldataload(0x3564)
                    let var8 := mulmod(a_4, a_18, R)
                    let var9 := addmod(var7, var8, R)
                    let a_5 := calldataload(0x33c4)
                    let a_19 := calldataload(0x3584)
                    let var10 := mulmod(a_5, a_19, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := addmod(a_32_prev_1, var11, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_32, var13, R)
                    let var15 := mulmod(var6, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_93 := calldataload(0x4544)
                    let var0 := 0x2
                    let var1 := sub(R, f_93)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_93, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_34 := calldataload(0x3764)
                    let a_34_prev_1 := calldataload(0x3924)
                    let var7 := 0x0
                    let a_6 := calldataload(0x33e4)
                    let a_20 := calldataload(0x35a4)
                    let var8 := mulmod(a_6, a_20, R)
                    let var9 := addmod(var7, var8, R)
                    let a_7 := calldataload(0x3404)
                    let a_21 := calldataload(0x35c4)
                    let var10 := mulmod(a_7, a_21, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := addmod(a_34_prev_1, var11, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_34, var13, R)
                    let var15 := mulmod(var6, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_94 := calldataload(0x4564)
                    let var0 := 0x1
                    let var1 := sub(R, f_94)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_94, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_36 := calldataload(0x37a4)
                    let a_36_prev_1 := calldataload(0x3944)
                    let var10 := 0x0
                    let a_8 := calldataload(0x3424)
                    let a_22 := calldataload(0x35e4)
                    let var11 := mulmod(a_8, a_22, R)
                    let var12 := addmod(var10, var11, R)
                    let a_9 := calldataload(0x3444)
                    let a_23 := calldataload(0x3604)
                    let var13 := mulmod(a_9, a_23, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := addmod(a_36_prev_1, var14, R)
                    let var16 := sub(R, var15)
                    let var17 := addmod(a_36, var16, R)
                    let var18 := mulmod(var9, var17, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var18, r)
                }
                {
                    let f_96 := calldataload(0x45a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_96)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_96, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_38 := calldataload(0x37e4)
                    let a_38_prev_1 := calldataload(0x3964)
                    let var10 := 0x0
                    let a_10 := calldataload(0x3464)
                    let a_24 := calldataload(0x3624)
                    let var11 := mulmod(a_10, a_24, R)
                    let var12 := addmod(var10, var11, R)
                    let a_11 := calldataload(0x3484)
                    let a_25 := calldataload(0x3644)
                    let var13 := mulmod(a_11, a_25, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := addmod(a_38_prev_1, var14, R)
                    let var16 := sub(R, var15)
                    let var17 := addmod(a_38, var16, R)
                    let var18 := mulmod(var9, var17, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var18, r)
                }
                {
                    let f_98 := calldataload(0x45e4)
                    let var0 := 0x1
                    let var1 := sub(R, f_98)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_98, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_40 := calldataload(0x3824)
                    let a_40_prev_1 := calldataload(0x3984)
                    let var7 := 0x0
                    let a_12 := calldataload(0x34a4)
                    let a_26 := calldataload(0x3664)
                    let var8 := mulmod(a_12, a_26, R)
                    let var9 := addmod(var7, var8, R)
                    let a_13 := calldataload(0x34c4)
                    let a_27 := calldataload(0x3684)
                    let var10 := mulmod(a_13, a_27, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := addmod(a_40_prev_1, var11, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_40, var13, R)
                    let var15 := mulmod(var6, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_89 := calldataload(0x44c4)
                    let var0 := 0x2
                    let var1 := sub(R, f_89)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_89, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_28 := calldataload(0x36a4)
                    let var7 := 0x0
                    let a_0 := calldataload(0x3324)
                    let a_14 := calldataload(0x34e4)
                    let var8 := mulmod(a_0, a_14, R)
                    let var9 := addmod(var7, var8, R)
                    let a_1 := calldataload(0x3344)
                    let a_15 := calldataload(0x3504)
                    let var10 := mulmod(a_1, a_15, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_28, var12, R)
                    let var14 := mulmod(var6, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_88 := calldataload(0x44a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_88)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_88, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_30 := calldataload(0x36e4)
                    let var10 := 0x0
                    let a_2 := calldataload(0x3364)
                    let a_16 := calldataload(0x3524)
                    let var11 := mulmod(a_2, a_16, R)
                    let var12 := addmod(var10, var11, R)
                    let a_3 := calldataload(0x3384)
                    let a_17 := calldataload(0x3544)
                    let var13 := mulmod(a_3, a_17, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := sub(R, var14)
                    let var16 := addmod(a_30, var15, R)
                    let var17 := mulmod(var9, var16, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var17, r)
                }
                {
                    let f_91 := calldataload(0x4504)
                    let var0 := 0x2
                    let var1 := sub(R, f_91)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_91, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_32 := calldataload(0x3724)
                    let var7 := 0x0
                    let a_4 := calldataload(0x33a4)
                    let a_18 := calldataload(0x3564)
                    let var8 := mulmod(a_4, a_18, R)
                    let var9 := addmod(var7, var8, R)
                    let a_5 := calldataload(0x33c4)
                    let a_19 := calldataload(0x3584)
                    let var10 := mulmod(a_5, a_19, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_32, var12, R)
                    let var14 := mulmod(var6, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_92 := calldataload(0x4524)
                    let var0 := 0x1
                    let var1 := sub(R, f_92)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_92, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_34 := calldataload(0x3764)
                    let var10 := 0x0
                    let a_6 := calldataload(0x33e4)
                    let a_20 := calldataload(0x35a4)
                    let var11 := mulmod(a_6, a_20, R)
                    let var12 := addmod(var10, var11, R)
                    let a_7 := calldataload(0x3404)
                    let a_21 := calldataload(0x35c4)
                    let var13 := mulmod(a_7, a_21, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := sub(R, var14)
                    let var16 := addmod(a_34, var15, R)
                    let var17 := mulmod(var9, var16, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var17, r)
                }
                {
                    let f_94 := calldataload(0x4564)
                    let var0 := 0x1
                    let var1 := sub(R, f_94)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_94, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_36 := calldataload(0x37a4)
                    let var10 := 0x0
                    let a_8 := calldataload(0x3424)
                    let a_22 := calldataload(0x35e4)
                    let var11 := mulmod(a_8, a_22, R)
                    let var12 := addmod(var10, var11, R)
                    let a_9 := calldataload(0x3444)
                    let a_23 := calldataload(0x3604)
                    let var13 := mulmod(a_9, a_23, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := sub(R, var14)
                    let var16 := addmod(a_36, var15, R)
                    let var17 := mulmod(var9, var16, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var17, r)
                }
                {
                    let f_96 := calldataload(0x45a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_96)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_96, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_38 := calldataload(0x37e4)
                    let var10 := 0x0
                    let a_10 := calldataload(0x3464)
                    let a_24 := calldataload(0x3624)
                    let var11 := mulmod(a_10, a_24, R)
                    let var12 := addmod(var10, var11, R)
                    let a_11 := calldataload(0x3484)
                    let a_25 := calldataload(0x3644)
                    let var13 := mulmod(a_11, a_25, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := sub(R, var14)
                    let var16 := addmod(a_38, var15, R)
                    let var17 := mulmod(var9, var16, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var17, r)
                }
                {
                    let f_98 := calldataload(0x45e4)
                    let var0 := 0x2
                    let var1 := sub(R, f_98)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_98, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_40 := calldataload(0x3824)
                    let var7 := 0x0
                    let a_12 := calldataload(0x34a4)
                    let a_26 := calldataload(0x3664)
                    let var8 := mulmod(a_12, a_26, R)
                    let var9 := addmod(var7, var8, R)
                    let a_13 := calldataload(0x34c4)
                    let a_27 := calldataload(0x3684)
                    let var10 := mulmod(a_13, a_27, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_40, var12, R)
                    let var14 := mulmod(var6, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_85 := calldataload(0x4444)
                    let var0 := 0x1
                    let var1 := sub(R, f_85)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_85, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_28 := calldataload(0x36a4)
                    let a_14 := calldataload(0x34e4)
                    let var10 := mulmod(var0, a_14, R)
                    let a_15 := calldataload(0x3504)
                    let var11 := mulmod(var10, a_15, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_28, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_90 := calldataload(0x44e4)
                    let var0 := 0x1
                    let var1 := sub(R, f_90)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_90, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_30 := calldataload(0x36e4)
                    let a_16 := calldataload(0x3524)
                    let var10 := mulmod(var0, a_16, R)
                    let a_17 := calldataload(0x3544)
                    let var11 := mulmod(var10, a_17, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_30, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_92 := calldataload(0x4524)
                    let var0 := 0x2
                    let var1 := sub(R, f_92)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_92, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_32 := calldataload(0x3724)
                    let var10 := 0x1
                    let a_18 := calldataload(0x3564)
                    let var11 := mulmod(var10, a_18, R)
                    let a_19 := calldataload(0x3584)
                    let var12 := mulmod(var11, a_19, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_32, var13, R)
                    let var15 := mulmod(var9, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_93 := calldataload(0x4544)
                    let var0 := 0x1
                    let var1 := sub(R, f_93)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_93, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_34 := calldataload(0x3764)
                    let a_20 := calldataload(0x35a4)
                    let var7 := mulmod(var0, a_20, R)
                    let a_21 := calldataload(0x35c4)
                    let var8 := mulmod(var7, a_21, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_34, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_95 := calldataload(0x4584)
                    let var0 := 0x1
                    let var1 := sub(R, f_95)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_95, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_36 := calldataload(0x37a4)
                    let a_22 := calldataload(0x35e4)
                    let var7 := mulmod(var0, a_22, R)
                    let a_23 := calldataload(0x3604)
                    let var8 := mulmod(var7, a_23, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_36, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_96 := calldataload(0x45a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_96)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_96, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_38 := calldataload(0x37e4)
                    let a_24 := calldataload(0x3624)
                    let var10 := mulmod(var0, a_24, R)
                    let a_25 := calldataload(0x3644)
                    let var11 := mulmod(var10, a_25, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_38, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_99 := calldataload(0x4604)
                    let var0 := 0x2
                    let var1 := sub(R, f_99)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_99, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_40 := calldataload(0x3824)
                    let var7 := 0x1
                    let a_26 := calldataload(0x3664)
                    let var8 := mulmod(var7, a_26, R)
                    let a_27 := calldataload(0x3684)
                    let var9 := mulmod(var8, a_27, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_40, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_86 := calldataload(0x4464)
                    let var0 := 0x1
                    let var1 := sub(R, f_86)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_86, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_28 := calldataload(0x36a4)
                    let a_28_prev_1 := calldataload(0x38c4)
                    let a_14 := calldataload(0x34e4)
                    let var7 := mulmod(var0, a_14, R)
                    let a_15 := calldataload(0x3504)
                    let var8 := mulmod(var7, a_15, R)
                    let var9 := mulmod(a_28_prev_1, var8, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_28, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_89 := calldataload(0x44c4)
                    let var0 := 0x1
                    let var1 := sub(R, f_89)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_89, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_30 := calldataload(0x36e4)
                    let a_30_prev_1 := calldataload(0x38e4)
                    let a_16 := calldataload(0x3524)
                    let var7 := mulmod(var0, a_16, R)
                    let a_17 := calldataload(0x3544)
                    let var8 := mulmod(var7, a_17, R)
                    let var9 := mulmod(a_30_prev_1, var8, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_30, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_91 := calldataload(0x4504)
                    let var0 := 0x1
                    let var1 := sub(R, f_91)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_91, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_32 := calldataload(0x3724)
                    let a_32_prev_1 := calldataload(0x3904)
                    let a_18 := calldataload(0x3564)
                    let var7 := mulmod(var0, a_18, R)
                    let a_19 := calldataload(0x3584)
                    let var8 := mulmod(var7, a_19, R)
                    let var9 := mulmod(a_32_prev_1, var8, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_32, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_93 := calldataload(0x4544)
                    let var0 := 0x1
                    let var1 := sub(R, f_93)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_93, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_34 := calldataload(0x3764)
                    let a_34_prev_1 := calldataload(0x3924)
                    let a_20 := calldataload(0x35a4)
                    let var7 := mulmod(var0, a_20, R)
                    let a_21 := calldataload(0x35c4)
                    let var8 := mulmod(var7, a_21, R)
                    let var9 := mulmod(a_34_prev_1, var8, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_34, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_95 := calldataload(0x4584)
                    let var0 := 0x2
                    let var1 := sub(R, f_95)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_95, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_36 := calldataload(0x37a4)
                    let a_36_prev_1 := calldataload(0x3944)
                    let var7 := 0x1
                    let a_22 := calldataload(0x35e4)
                    let var8 := mulmod(var7, a_22, R)
                    let a_23 := calldataload(0x3604)
                    let var9 := mulmod(var8, a_23, R)
                    let var10 := mulmod(a_36_prev_1, var9, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_36, var11, R)
                    let var13 := mulmod(var6, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_97 := calldataload(0x45c4)
                    let var0 := 0x2
                    let var1 := sub(R, f_97)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_97, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_38 := calldataload(0x37e4)
                    let a_38_prev_1 := calldataload(0x3964)
                    let var7 := 0x1
                    let a_24 := calldataload(0x3624)
                    let var8 := mulmod(var7, a_24, R)
                    let a_25 := calldataload(0x3644)
                    let var9 := mulmod(var8, a_25, R)
                    let var10 := mulmod(a_38_prev_1, var9, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_38, var11, R)
                    let var13 := mulmod(var6, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_98 := calldataload(0x45e4)
                    let var0 := 0x1
                    let var1 := sub(R, f_98)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_98, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_40 := calldataload(0x3824)
                    let a_40_prev_1 := calldataload(0x3984)
                    let a_26 := calldataload(0x3664)
                    let var7 := mulmod(var0, a_26, R)
                    let a_27 := calldataload(0x3684)
                    let var8 := mulmod(var7, a_27, R)
                    let var9 := mulmod(a_40_prev_1, var8, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_40, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_87 := calldataload(0x4484)
                    let var0 := 0x1
                    let var1 := sub(R, f_87)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_87, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_28 := calldataload(0x36a4)
                    let var10 := 0x0
                    let a_14 := calldataload(0x34e4)
                    let var11 := addmod(var10, a_14, R)
                    let a_15 := calldataload(0x3504)
                    let var12 := addmod(var11, a_15, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_28, var13, R)
                    let var15 := mulmod(var9, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_90 := calldataload(0x44e4)
                    let var0 := 0x1
                    let var1 := sub(R, f_90)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_90, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_30 := calldataload(0x36e4)
                    let var10 := 0x0
                    let a_16 := calldataload(0x3524)
                    let var11 := addmod(var10, a_16, R)
                    let a_17 := calldataload(0x3544)
                    let var12 := addmod(var11, a_17, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_30, var13, R)
                    let var15 := mulmod(var9, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_92 := calldataload(0x4524)
                    let var0 := 0x1
                    let var1 := sub(R, f_92)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_92, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_32 := calldataload(0x3724)
                    let var10 := 0x0
                    let a_18 := calldataload(0x3564)
                    let var11 := addmod(var10, a_18, R)
                    let a_19 := calldataload(0x3584)
                    let var12 := addmod(var11, a_19, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_32, var13, R)
                    let var15 := mulmod(var9, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_94 := calldataload(0x4564)
                    let var0 := 0x1
                    let var1 := sub(R, f_94)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_94, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_34 := calldataload(0x3764)
                    let var10 := 0x0
                    let a_20 := calldataload(0x35a4)
                    let var11 := addmod(var10, a_20, R)
                    let a_21 := calldataload(0x35c4)
                    let var12 := addmod(var11, a_21, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_34, var13, R)
                    let var15 := mulmod(var9, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_96 := calldataload(0x45a4)
                    let var0 := 0x2
                    let var1 := sub(R, f_96)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_96, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_36 := calldataload(0x37a4)
                    let var10 := 0x0
                    let a_22 := calldataload(0x35e4)
                    let var11 := addmod(var10, a_22, R)
                    let a_23 := calldataload(0x3604)
                    let var12 := addmod(var11, a_23, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_36, var13, R)
                    let var15 := mulmod(var9, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_97 := calldataload(0x45c4)
                    let var0 := 0x1
                    let var1 := sub(R, f_97)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_97, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_38 := calldataload(0x37e4)
                    let var7 := 0x0
                    let a_24 := calldataload(0x3624)
                    let var8 := addmod(var7, a_24, R)
                    let a_25 := calldataload(0x3644)
                    let var9 := addmod(var8, a_25, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_38, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_99 := calldataload(0x4604)
                    let var0 := 0x1
                    let var1 := sub(R, f_99)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_99, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_40 := calldataload(0x3824)
                    let var7 := 0x0
                    let a_26 := calldataload(0x3664)
                    let var8 := addmod(var7, a_26, R)
                    let a_27 := calldataload(0x3684)
                    let var9 := addmod(var8, a_27, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_40, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_87 := calldataload(0x4484)
                    let var0 := 0x1
                    let var1 := sub(R, f_87)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_87, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_28 := calldataload(0x36a4)
                    let a_28_prev_1 := calldataload(0x38c4)
                    let var10 := 0x0
                    let a_14 := calldataload(0x34e4)
                    let var11 := addmod(var10, a_14, R)
                    let a_15 := calldataload(0x3504)
                    let var12 := addmod(var11, a_15, R)
                    let var13 := addmod(a_28_prev_1, var12, R)
                    let var14 := sub(R, var13)
                    let var15 := addmod(a_28, var14, R)
                    let var16 := mulmod(var9, var15, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var16, r)
                }
                {
                    let f_90 := calldataload(0x44e4)
                    let var0 := 0x1
                    let var1 := sub(R, f_90)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_90, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_30 := calldataload(0x36e4)
                    let a_30_prev_1 := calldataload(0x38e4)
                    let var10 := 0x0
                    let a_16 := calldataload(0x3524)
                    let var11 := addmod(var10, a_16, R)
                    let a_17 := calldataload(0x3544)
                    let var12 := addmod(var11, a_17, R)
                    let var13 := addmod(a_30_prev_1, var12, R)
                    let var14 := sub(R, var13)
                    let var15 := addmod(a_30, var14, R)
                    let var16 := mulmod(var9, var15, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var16, r)
                }
                {
                    let f_92 := calldataload(0x4524)
                    let var0 := 0x1
                    let var1 := sub(R, f_92)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_92, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_32 := calldataload(0x3724)
                    let a_32_prev_1 := calldataload(0x3904)
                    let var10 := 0x0
                    let a_18 := calldataload(0x3564)
                    let var11 := addmod(var10, a_18, R)
                    let a_19 := calldataload(0x3584)
                    let var12 := addmod(var11, a_19, R)
                    let var13 := addmod(a_32_prev_1, var12, R)
                    let var14 := sub(R, var13)
                    let var15 := addmod(a_32, var14, R)
                    let var16 := mulmod(var9, var15, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var16, r)
                }
                {
                    let f_94 := calldataload(0x4564)
                    let var0 := 0x2
                    let var1 := sub(R, f_94)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_94, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_34 := calldataload(0x3764)
                    let a_34_prev_1 := calldataload(0x3924)
                    let var10 := 0x0
                    let a_20 := calldataload(0x35a4)
                    let var11 := addmod(var10, a_20, R)
                    let a_21 := calldataload(0x35c4)
                    let var12 := addmod(var11, a_21, R)
                    let var13 := addmod(a_34_prev_1, var12, R)
                    let var14 := sub(R, var13)
                    let var15 := addmod(a_34, var14, R)
                    let var16 := mulmod(var9, var15, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var16, r)
                }
                {
                    let f_95 := calldataload(0x4584)
                    let var0 := 0x1
                    let var1 := sub(R, f_95)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_95, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_36 := calldataload(0x37a4)
                    let a_36_prev_1 := calldataload(0x3944)
                    let var7 := 0x0
                    let a_22 := calldataload(0x35e4)
                    let var8 := addmod(var7, a_22, R)
                    let a_23 := calldataload(0x3604)
                    let var9 := addmod(var8, a_23, R)
                    let var10 := addmod(a_36_prev_1, var9, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_36, var11, R)
                    let var13 := mulmod(var6, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_97 := calldataload(0x45c4)
                    let var0 := 0x1
                    let var1 := sub(R, f_97)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_97, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_38 := calldataload(0x37e4)
                    let a_38_prev_1 := calldataload(0x3964)
                    let var7 := 0x0
                    let a_24 := calldataload(0x3624)
                    let var8 := addmod(var7, a_24, R)
                    let a_25 := calldataload(0x3644)
                    let var9 := addmod(var8, a_25, R)
                    let var10 := addmod(a_38_prev_1, var9, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_38, var11, R)
                    let var13 := mulmod(var6, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_99 := calldataload(0x4604)
                    let var0 := 0x1
                    let var1 := sub(R, f_99)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_99, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_40 := calldataload(0x3824)
                    let a_40_prev_1 := calldataload(0x3984)
                    let var7 := 0x0
                    let a_26 := calldataload(0x3664)
                    let var8 := addmod(var7, a_26, R)
                    let a_27 := calldataload(0x3684)
                    let var9 := addmod(var8, a_27, R)
                    let var10 := addmod(a_40_prev_1, var9, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_40, var11, R)
                    let var13 := mulmod(var6, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_6 := calldataload(0x3a64)
                    let var0 := 0x0
                    let var1 := mulmod(f_6, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_7 := calldataload(0x3a84)
                    let var0 := 0x0
                    let var1 := mulmod(f_7, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_8 := calldataload(0x3aa4)
                    let var0 := 0x0
                    let var1 := mulmod(f_8, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_9 := calldataload(0x3ac4)
                    let var0 := 0x0
                    let var1 := mulmod(f_9, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_10 := calldataload(0x3ae4)
                    let var0 := 0x0
                    let var1 := mulmod(f_10, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_11 := calldataload(0x3b04)
                    let var0 := 0x0
                    let var1 := mulmod(f_11, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_12 := calldataload(0x3b24)
                    let var0 := 0x0
                    let var1 := mulmod(f_12, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_13 := calldataload(0x3b44)
                    let var0 := 0x0
                    let var1 := mulmod(f_13, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_14 := calldataload(0x3b64)
                    let var0 := 0x0
                    let var1 := mulmod(f_14, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_15 := calldataload(0x3b84)
                    let var0 := 0x0
                    let var1 := mulmod(f_15, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_16 := calldataload(0x3ba4)
                    let var0 := 0x0
                    let var1 := mulmod(f_16, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_17 := calldataload(0x3bc4)
                    let var0 := 0x0
                    let var1 := mulmod(f_17, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_18 := calldataload(0x3be4)
                    let var0 := 0x0
                    let var1 := mulmod(f_18, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_19 := calldataload(0x3c04)
                    let var0 := 0x0
                    let var1 := mulmod(f_19, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_20 := calldataload(0x3c24)
                    let var0 := 0x0
                    let var1 := mulmod(f_20, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_21 := calldataload(0x3c44)
                    let var0 := 0x0
                    let var1 := mulmod(f_21, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_22 := calldataload(0x3c64)
                    let var0 := 0x0
                    let var1 := mulmod(f_22, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_23 := calldataload(0x3c84)
                    let var0 := 0x0
                    let var1 := mulmod(f_23, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_24 := calldataload(0x3ca4)
                    let var0 := 0x0
                    let var1 := mulmod(f_24, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_25 := calldataload(0x3cc4)
                    let var0 := 0x0
                    let var1 := mulmod(f_25, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_26 := calldataload(0x3ce4)
                    let var0 := 0x0
                    let var1 := mulmod(f_26, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_27 := calldataload(0x3d04)
                    let var0 := 0x0
                    let var1 := mulmod(f_27, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_28 := calldataload(0x3d24)
                    let var0 := 0x0
                    let var1 := mulmod(f_28, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_29 := calldataload(0x3d44)
                    let var0 := 0x0
                    let var1 := mulmod(f_29, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_30 := calldataload(0x3d64)
                    let var0 := 0x0
                    let var1 := mulmod(f_30, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_31 := calldataload(0x3d84)
                    let var0 := 0x0
                    let var1 := mulmod(f_31, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_32 := calldataload(0x3da4)
                    let var0 := 0x0
                    let var1 := mulmod(f_32, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_33 := calldataload(0x3dc4)
                    let var0 := 0x0
                    let var1 := mulmod(f_33, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_34 := calldataload(0x3de4)
                    let var0 := 0x0
                    let var1 := mulmod(f_34, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_35 := calldataload(0x3e04)
                    let var0 := 0x0
                    let var1 := mulmod(f_35, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_36 := calldataload(0x3e24)
                    let var0 := 0x0
                    let var1 := mulmod(f_36, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_37 := calldataload(0x3e44)
                    let var0 := 0x0
                    let var1 := mulmod(f_37, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_38 := calldataload(0x3e64)
                    let var0 := 0x0
                    let var1 := mulmod(f_38, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_39 := calldataload(0x3e84)
                    let var0 := 0x0
                    let var1 := mulmod(f_39, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_40 := calldataload(0x3ea4)
                    let var0 := 0x0
                    let var1 := mulmod(f_40, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_41 := calldataload(0x3ec4)
                    let var0 := 0x0
                    let var1 := mulmod(f_41, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_42 := calldataload(0x3ee4)
                    let var0 := 0x0
                    let var1 := mulmod(f_42, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_43 := calldataload(0x3f04)
                    let var0 := 0x0
                    let var1 := mulmod(f_43, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_44 := calldataload(0x3f24)
                    let var0 := 0x0
                    let var1 := mulmod(f_44, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_45 := calldataload(0x3f44)
                    let var0 := 0x0
                    let var1 := mulmod(f_45, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_46 := calldataload(0x3f64)
                    let var0 := 0x0
                    let var1 := mulmod(f_46, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_47 := calldataload(0x3f84)
                    let var0 := 0x0
                    let var1 := mulmod(f_47, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_48 := calldataload(0x3fa4)
                    let var0 := 0x0
                    let var1 := mulmod(f_48, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_49 := calldataload(0x3fc4)
                    let var0 := 0x0
                    let var1 := mulmod(f_49, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_50 := calldataload(0x3fe4)
                    let var0 := 0x0
                    let var1 := mulmod(f_50, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_51 := calldataload(0x4004)
                    let var0 := 0x0
                    let var1 := mulmod(f_51, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_52 := calldataload(0x4024)
                    let var0 := 0x0
                    let var1 := mulmod(f_52, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_53 := calldataload(0x4044)
                    let var0 := 0x0
                    let var1 := mulmod(f_53, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_54 := calldataload(0x4064)
                    let var0 := 0x0
                    let var1 := mulmod(f_54, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_55 := calldataload(0x4084)
                    let var0 := 0x0
                    let var1 := mulmod(f_55, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_56 := calldataload(0x40a4)
                    let var0 := 0x0
                    let var1 := mulmod(f_56, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_57 := calldataload(0x40c4)
                    let var0 := 0x0
                    let var1 := mulmod(f_57, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_58 := calldataload(0x40e4)
                    let var0 := 0x0
                    let var1 := mulmod(f_58, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_59 := calldataload(0x4104)
                    let var0 := 0x0
                    let var1 := mulmod(f_59, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_60 := calldataload(0x4124)
                    let var0 := 0x0
                    let var1 := mulmod(f_60, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_61 := calldataload(0x4144)
                    let var0 := 0x0
                    let var1 := mulmod(f_61, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(R, mulmod(l_0, calldataload(0x4c24), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x5044)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, R), sub(R, perm_z_last), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4c84), sub(R, calldataload(0x4c64)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4ce4), sub(R, calldataload(0x4cc4)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4d44), sub(R, calldataload(0x4d24)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4da4), sub(R, calldataload(0x4d84)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4e04), sub(R, calldataload(0x4de4)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4e64), sub(R, calldataload(0x4e44)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4ec4), sub(R, calldataload(0x4ea4)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4f24), sub(R, calldataload(0x4f04)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4f84), sub(R, calldataload(0x4f64)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x4fe4), sub(R, calldataload(0x4fc4)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x5044), sub(R, calldataload(0x5024)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4c44)
                    let rhs := calldataload(0x4c24)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3324), mulmod(beta, calldataload(0x4644), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3344), mulmod(beta, calldataload(0x4664), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3364), mulmod(beta, calldataload(0x4684), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3384), mulmod(beta, calldataload(0x46a4), R), R), gamma, R), R)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3324), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3344), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3364), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3384), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4ca4)
                    let rhs := calldataload(0x4c84)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x33a4), mulmod(beta, calldataload(0x46c4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x33c4), mulmod(beta, calldataload(0x46e4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x33e4), mulmod(beta, calldataload(0x4704), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3404), mulmod(beta, calldataload(0x4724), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x33a4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x33c4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x33e4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3404), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4d04)
                    let rhs := calldataload(0x4ce4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3424), mulmod(beta, calldataload(0x4744), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3444), mulmod(beta, calldataload(0x4764), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3464), mulmod(beta, calldataload(0x4784), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3484), mulmod(beta, calldataload(0x47a4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3424), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3444), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3464), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3484), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4d64)
                    let rhs := calldataload(0x4d44)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x34a4), mulmod(beta, calldataload(0x47c4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x34c4), mulmod(beta, calldataload(0x47e4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x34e4), mulmod(beta, calldataload(0x4804), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3504), mulmod(beta, calldataload(0x4824), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x34a4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x34c4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x34e4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3504), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4dc4)
                    let rhs := calldataload(0x4da4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3524), mulmod(beta, calldataload(0x4844), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3544), mulmod(beta, calldataload(0x4864), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3564), mulmod(beta, calldataload(0x4884), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3584), mulmod(beta, calldataload(0x48a4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3524), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3544), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3564), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3584), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4e24)
                    let rhs := calldataload(0x4e04)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x35a4), mulmod(beta, calldataload(0x48c4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x35c4), mulmod(beta, calldataload(0x48e4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x35e4), mulmod(beta, calldataload(0x4904), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3604), mulmod(beta, calldataload(0x4924), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x35a4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x35c4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x35e4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3604), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4e84)
                    let rhs := calldataload(0x4e64)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3624), mulmod(beta, calldataload(0x4944), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3644), mulmod(beta, calldataload(0x4964), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3664), mulmod(beta, calldataload(0x4984), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3684), mulmod(beta, calldataload(0x49a4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3624), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3644), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3664), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3684), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4ee4)
                    let rhs := calldataload(0x4ec4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x36a4), mulmod(beta, calldataload(0x49c4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x36c4), mulmod(beta, calldataload(0x49e4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x36e4), mulmod(beta, calldataload(0x4a04), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3704), mulmod(beta, calldataload(0x4a24), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x36a4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x36c4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x36e4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3704), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4f44)
                    let rhs := calldataload(0x4f24)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3724), mulmod(beta, calldataload(0x4a44), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3744), mulmod(beta, calldataload(0x4a64), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3764), mulmod(beta, calldataload(0x4a84), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3784), mulmod(beta, calldataload(0x4aa4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3724), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3744), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3764), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3784), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x4fa4)
                    let rhs := calldataload(0x4f84)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x37a4), mulmod(beta, calldataload(0x4ac4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x37c4), mulmod(beta, calldataload(0x4ae4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x37e4), mulmod(beta, calldataload(0x4b04), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3804), mulmod(beta, calldataload(0x4b24), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x37a4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x37c4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x37e4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3804), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x5004)
                    let rhs := calldataload(0x4fe4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3824), mulmod(beta, calldataload(0x4b44), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3844), mulmod(beta, calldataload(0x4b64), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3864), mulmod(beta, calldataload(0x4b84), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x3884), mulmod(beta, calldataload(0x4ba4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3824), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3844), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3864), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x3884), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x5064)
                    let rhs := calldataload(0x5044)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x38a4), mulmod(beta, calldataload(0x4bc4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x39a4), mulmod(beta, calldataload(0x4be4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x4c04), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x38a4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x39a4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), R), gamma, R), R)
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5084), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5084), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_63 := calldataload(0x4184)
                        let var1 := mulmod(var0, f_63, R)
                        let a_0 := calldataload(0x3324)
                        let var2 := mulmod(a_0, f_63, R)
                        let a_14 := calldataload(0x34e4)
                        let var3 := mulmod(a_14, f_63, R)
                        let a_28 := calldataload(0x36a4)
                        let var4 := mulmod(a_28, f_63, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x50c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x50a4), sub(R, calldataload(0x5084)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x50e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x50e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_64 := calldataload(0x41a4)
                        let var1 := mulmod(var0, f_64, R)
                        let a_1 := calldataload(0x3344)
                        let var2 := mulmod(a_1, f_64, R)
                        let a_15 := calldataload(0x3504)
                        let var3 := mulmod(a_15, f_64, R)
                        let a_29 := calldataload(0x36c4)
                        let var4 := mulmod(a_29, f_64, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5124), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5104), sub(R, calldataload(0x50e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5144), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5144), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_65 := calldataload(0x41c4)
                        let var1 := mulmod(var0, f_65, R)
                        let a_2 := calldataload(0x3364)
                        let var2 := mulmod(a_2, f_65, R)
                        let a_16 := calldataload(0x3524)
                        let var3 := mulmod(a_16, f_65, R)
                        let a_30 := calldataload(0x36e4)
                        let var4 := mulmod(a_30, f_65, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5184), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5164), sub(R, calldataload(0x5144)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x51a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x51a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_66 := calldataload(0x41e4)
                        let var1 := mulmod(var0, f_66, R)
                        let a_3 := calldataload(0x3384)
                        let var2 := mulmod(a_3, f_66, R)
                        let a_17 := calldataload(0x3544)
                        let var3 := mulmod(a_17, f_66, R)
                        let a_31 := calldataload(0x3704)
                        let var4 := mulmod(a_31, f_66, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x51e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x51c4), sub(R, calldataload(0x51a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5204), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5204), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_67 := calldataload(0x4204)
                        let var1 := mulmod(var0, f_67, R)
                        let a_4 := calldataload(0x33a4)
                        let var2 := mulmod(a_4, f_67, R)
                        let a_18 := calldataload(0x3564)
                        let var3 := mulmod(a_18, f_67, R)
                        let a_32 := calldataload(0x3724)
                        let var4 := mulmod(a_32, f_67, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5244), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5224), sub(R, calldataload(0x5204)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5264), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5264), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_68 := calldataload(0x4224)
                        let var1 := mulmod(var0, f_68, R)
                        let a_5 := calldataload(0x33c4)
                        let var2 := mulmod(a_5, f_68, R)
                        let a_19 := calldataload(0x3584)
                        let var3 := mulmod(a_19, f_68, R)
                        let a_33 := calldataload(0x3744)
                        let var4 := mulmod(a_33, f_68, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x52a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5284), sub(R, calldataload(0x5264)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x52c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x52c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_69 := calldataload(0x4244)
                        let var1 := mulmod(var0, f_69, R)
                        let a_6 := calldataload(0x33e4)
                        let var2 := mulmod(a_6, f_69, R)
                        let a_20 := calldataload(0x35a4)
                        let var3 := mulmod(a_20, f_69, R)
                        let a_34 := calldataload(0x3764)
                        let var4 := mulmod(a_34, f_69, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5304), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x52e4), sub(R, calldataload(0x52c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5324), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5324), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_70 := calldataload(0x4264)
                        let var1 := mulmod(var0, f_70, R)
                        let a_7 := calldataload(0x3404)
                        let var2 := mulmod(a_7, f_70, R)
                        let a_21 := calldataload(0x35c4)
                        let var3 := mulmod(a_21, f_70, R)
                        let a_35 := calldataload(0x3784)
                        let var4 := mulmod(a_35, f_70, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5364), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5344), sub(R, calldataload(0x5324)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5384), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5384), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_71 := calldataload(0x4284)
                        let var1 := mulmod(var0, f_71, R)
                        let a_8 := calldataload(0x3424)
                        let var2 := mulmod(a_8, f_71, R)
                        let a_22 := calldataload(0x35e4)
                        let var3 := mulmod(a_22, f_71, R)
                        let a_36 := calldataload(0x37a4)
                        let var4 := mulmod(a_36, f_71, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x53c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x53a4), sub(R, calldataload(0x5384)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x53e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x53e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_72 := calldataload(0x42a4)
                        let var1 := mulmod(var0, f_72, R)
                        let a_9 := calldataload(0x3444)
                        let var2 := mulmod(a_9, f_72, R)
                        let a_23 := calldataload(0x3604)
                        let var3 := mulmod(a_23, f_72, R)
                        let a_37 := calldataload(0x37c4)
                        let var4 := mulmod(a_37, f_72, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5424), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5404), sub(R, calldataload(0x53e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5444), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5444), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_73 := calldataload(0x42c4)
                        let var1 := mulmod(var0, f_73, R)
                        let a_10 := calldataload(0x3464)
                        let var2 := mulmod(a_10, f_73, R)
                        let a_24 := calldataload(0x3624)
                        let var3 := mulmod(a_24, f_73, R)
                        let a_38 := calldataload(0x37e4)
                        let var4 := mulmod(a_38, f_73, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5484), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5464), sub(R, calldataload(0x5444)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x54a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x54a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_74 := calldataload(0x42e4)
                        let var1 := mulmod(var0, f_74, R)
                        let a_11 := calldataload(0x3484)
                        let var2 := mulmod(a_11, f_74, R)
                        let a_25 := calldataload(0x3644)
                        let var3 := mulmod(a_25, f_74, R)
                        let a_39 := calldataload(0x3804)
                        let var4 := mulmod(a_39, f_74, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x54e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x54c4), sub(R, calldataload(0x54a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5504), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5504), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_75 := calldataload(0x4304)
                        let var1 := mulmod(var0, f_75, R)
                        let a_12 := calldataload(0x34a4)
                        let var2 := mulmod(a_12, f_75, R)
                        let a_26 := calldataload(0x3664)
                        let var3 := mulmod(a_26, f_75, R)
                        let a_40 := calldataload(0x3824)
                        let var4 := mulmod(a_40, f_75, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5544), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5524), sub(R, calldataload(0x5504)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5564), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5564), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_62 := calldataload(0x4164)
                        let var1 := mulmod(var0, f_62, R)
                        let a_42 := calldataload(0x3864)
                        let var2 := mulmod(a_42, f_62, R)
                        let a_43 := calldataload(0x3884)
                        let var3 := mulmod(a_43, f_62, R)
                        let a_44 := calldataload(0x38a4)
                        let var4 := mulmod(a_44, f_62, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_76 := calldataload(0x4324)
                        let var1 := mulmod(var0, f_76, R)
                        let a_13 := calldataload(0x34c4)
                        let var2 := mulmod(a_13, f_76, R)
                        let a_27 := calldataload(0x3684)
                        let var3 := mulmod(a_27, f_76, R)
                        let a_41 := calldataload(0x3844)
                        let var4 := mulmod(a_41, f_76, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x55a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5584), sub(R, calldataload(0x5564)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x55c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x55c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_6 := calldataload(0x3a64)
                        let var0 := 0x1
                        let var1 := mulmod(f_6, var0, R)
                        let a_0 := calldataload(0x3324)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_28 := calldataload(0x36a4)
                        let var8 := mulmod(var1, a_28, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5604), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x55e4), sub(R, calldataload(0x55c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5624), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5624), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x3a84)
                        let var0 := 0x1
                        let var1 := mulmod(f_7, var0, R)
                        let a_1 := calldataload(0x3344)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_29 := calldataload(0x36c4)
                        let var8 := mulmod(var1, a_29, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5664), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5644), sub(R, calldataload(0x5624)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5684), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5684), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x3aa4)
                        let var0 := 0x1
                        let var1 := mulmod(f_8, var0, R)
                        let a_2 := calldataload(0x3364)
                        let var2 := mulmod(var1, a_2, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_30 := calldataload(0x36e4)
                        let var8 := mulmod(var1, a_30, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x56c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x56a4), sub(R, calldataload(0x5684)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x56e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x56e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_9 := calldataload(0x3ac4)
                        let var0 := 0x1
                        let var1 := mulmod(f_9, var0, R)
                        let a_3 := calldataload(0x3384)
                        let var2 := mulmod(var1, a_3, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_31 := calldataload(0x3704)
                        let var8 := mulmod(var1, a_31, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5724), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5704), sub(R, calldataload(0x56e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5744), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5744), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_10 := calldataload(0x3ae4)
                        let var0 := 0x1
                        let var1 := mulmod(f_10, var0, R)
                        let a_4 := calldataload(0x33a4)
                        let var2 := mulmod(var1, a_4, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_32 := calldataload(0x3724)
                        let var8 := mulmod(var1, a_32, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5784), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5764), sub(R, calldataload(0x5744)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x57a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x57a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_11 := calldataload(0x3b04)
                        let var0 := 0x1
                        let var1 := mulmod(f_11, var0, R)
                        let a_5 := calldataload(0x33c4)
                        let var2 := mulmod(var1, a_5, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_33 := calldataload(0x3744)
                        let var8 := mulmod(var1, a_33, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x57e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x57c4), sub(R, calldataload(0x57a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5804), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5804), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_12 := calldataload(0x3b24)
                        let var0 := 0x1
                        let var1 := mulmod(f_12, var0, R)
                        let a_6 := calldataload(0x33e4)
                        let var2 := mulmod(var1, a_6, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_34 := calldataload(0x3764)
                        let var8 := mulmod(var1, a_34, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5844), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5824), sub(R, calldataload(0x5804)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5864), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5864), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_13 := calldataload(0x3b44)
                        let var0 := 0x1
                        let var1 := mulmod(f_13, var0, R)
                        let a_7 := calldataload(0x3404)
                        let var2 := mulmod(var1, a_7, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_35 := calldataload(0x3784)
                        let var8 := mulmod(var1, a_35, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x58a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5884), sub(R, calldataload(0x5864)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x58c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x58c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_14 := calldataload(0x3b64)
                        let var0 := 0x1
                        let var1 := mulmod(f_14, var0, R)
                        let a_8 := calldataload(0x3424)
                        let var2 := mulmod(var1, a_8, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_36 := calldataload(0x37a4)
                        let var8 := mulmod(var1, a_36, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5904), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x58e4), sub(R, calldataload(0x58c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5924), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5924), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_15 := calldataload(0x3b84)
                        let var0 := 0x1
                        let var1 := mulmod(f_15, var0, R)
                        let a_9 := calldataload(0x3444)
                        let var2 := mulmod(var1, a_9, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_37 := calldataload(0x37c4)
                        let var8 := mulmod(var1, a_37, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5964), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5944), sub(R, calldataload(0x5924)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5984), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5984), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_16 := calldataload(0x3ba4)
                        let var0 := 0x1
                        let var1 := mulmod(f_16, var0, R)
                        let a_10 := calldataload(0x3464)
                        let var2 := mulmod(var1, a_10, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_38 := calldataload(0x37e4)
                        let var8 := mulmod(var1, a_38, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x59c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x59a4), sub(R, calldataload(0x5984)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x59e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x59e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_17 := calldataload(0x3bc4)
                        let var0 := 0x1
                        let var1 := mulmod(f_17, var0, R)
                        let a_11 := calldataload(0x3484)
                        let var2 := mulmod(var1, a_11, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_39 := calldataload(0x3804)
                        let var8 := mulmod(var1, a_39, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5a24), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5a04), sub(R, calldataload(0x59e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5a44), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5a44), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_18 := calldataload(0x3be4)
                        let var0 := 0x1
                        let var1 := mulmod(f_18, var0, R)
                        let a_12 := calldataload(0x34a4)
                        let var2 := mulmod(var1, a_12, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_40 := calldataload(0x3824)
                        let var8 := mulmod(var1, a_40, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5a84), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5a64), sub(R, calldataload(0x5a44)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5aa4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5aa4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x39c4)
                        let f_2 := calldataload(0x39e4)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_19 := calldataload(0x3c04)
                        let var0 := 0x1
                        let var1 := mulmod(f_19, var0, R)
                        let a_13 := calldataload(0x34c4)
                        let var2 := mulmod(var1, a_13, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efff8001
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_41 := calldataload(0x3844)
                        let var8 := mulmod(var1, a_41, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5ae4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5ac4), sub(R, calldataload(0x5aa4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5b04), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5b04), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_20 := calldataload(0x3c24)
                        let var0 := 0x1
                        let var1 := mulmod(f_20, var0, R)
                        let a_0 := calldataload(0x3324)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5b44), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5b24), sub(R, calldataload(0x5b04)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5b64), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5b64), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_21 := calldataload(0x3c44)
                        let var0 := 0x1
                        let var1 := mulmod(f_21, var0, R)
                        let a_1 := calldataload(0x3344)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5ba4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5b84), sub(R, calldataload(0x5b64)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5bc4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5bc4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_22 := calldataload(0x3c64)
                        let var0 := 0x1
                        let var1 := mulmod(f_22, var0, R)
                        let a_2 := calldataload(0x3364)
                        let var2 := mulmod(var1, a_2, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5c04), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5be4), sub(R, calldataload(0x5bc4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5c24), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5c24), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_23 := calldataload(0x3c84)
                        let var0 := 0x1
                        let var1 := mulmod(f_23, var0, R)
                        let a_3 := calldataload(0x3384)
                        let var2 := mulmod(var1, a_3, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5c64), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5c44), sub(R, calldataload(0x5c24)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5c84), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5c84), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_24 := calldataload(0x3ca4)
                        let var0 := 0x1
                        let var1 := mulmod(f_24, var0, R)
                        let a_4 := calldataload(0x33a4)
                        let var2 := mulmod(var1, a_4, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5cc4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5ca4), sub(R, calldataload(0x5c84)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5ce4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5ce4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_25 := calldataload(0x3cc4)
                        let var0 := 0x1
                        let var1 := mulmod(f_25, var0, R)
                        let a_5 := calldataload(0x33c4)
                        let var2 := mulmod(var1, a_5, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5d24), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5d04), sub(R, calldataload(0x5ce4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5d44), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5d44), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_26 := calldataload(0x3ce4)
                        let var0 := 0x1
                        let var1 := mulmod(f_26, var0, R)
                        let a_6 := calldataload(0x33e4)
                        let var2 := mulmod(var1, a_6, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5d84), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5d64), sub(R, calldataload(0x5d44)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5da4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5da4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_27 := calldataload(0x3d04)
                        let var0 := 0x1
                        let var1 := mulmod(f_27, var0, R)
                        let a_7 := calldataload(0x3404)
                        let var2 := mulmod(var1, a_7, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5de4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5dc4), sub(R, calldataload(0x5da4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5e04), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5e04), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_28 := calldataload(0x3d24)
                        let var0 := 0x1
                        let var1 := mulmod(f_28, var0, R)
                        let a_8 := calldataload(0x3424)
                        let var2 := mulmod(var1, a_8, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5e44), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5e24), sub(R, calldataload(0x5e04)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5e64), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5e64), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_29 := calldataload(0x3d44)
                        let var0 := 0x1
                        let var1 := mulmod(f_29, var0, R)
                        let a_9 := calldataload(0x3444)
                        let var2 := mulmod(var1, a_9, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5ea4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5e84), sub(R, calldataload(0x5e64)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5ec4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5ec4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_30 := calldataload(0x3d64)
                        let var0 := 0x1
                        let var1 := mulmod(f_30, var0, R)
                        let a_10 := calldataload(0x3464)
                        let var2 := mulmod(var1, a_10, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5f04), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5ee4), sub(R, calldataload(0x5ec4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5f24), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5f24), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_31 := calldataload(0x3d84)
                        let var0 := 0x1
                        let var1 := mulmod(f_31, var0, R)
                        let a_11 := calldataload(0x3484)
                        let var2 := mulmod(var1, a_11, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5f64), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5f44), sub(R, calldataload(0x5f24)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5f84), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5f84), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_32 := calldataload(0x3da4)
                        let var0 := 0x1
                        let var1 := mulmod(f_32, var0, R)
                        let a_12 := calldataload(0x34a4)
                        let var2 := mulmod(var1, a_12, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x5fc4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x5fa4), sub(R, calldataload(0x5f84)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x5fe4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x5fe4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x3a04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_33 := calldataload(0x3dc4)
                        let var0 := 0x1
                        let var1 := mulmod(f_33, var0, R)
                        let a_13 := calldataload(0x34c4)
                        let var2 := mulmod(var1, a_13, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6024), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6004), sub(R, calldataload(0x5fe4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6044), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6044), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_34 := calldataload(0x3de4)
                        let var0 := 0x1
                        let var1 := mulmod(f_34, var0, R)
                        let a_0 := calldataload(0x3324)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6084), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6064), sub(R, calldataload(0x6044)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x60a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x60a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_35 := calldataload(0x3e04)
                        let var0 := 0x1
                        let var1 := mulmod(f_35, var0, R)
                        let a_1 := calldataload(0x3344)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x60e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x60c4), sub(R, calldataload(0x60a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6104), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6104), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_36 := calldataload(0x3e24)
                        let var0 := 0x1
                        let var1 := mulmod(f_36, var0, R)
                        let a_2 := calldataload(0x3364)
                        let var2 := mulmod(var1, a_2, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6144), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6124), sub(R, calldataload(0x6104)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6164), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6164), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_37 := calldataload(0x3e44)
                        let var0 := 0x1
                        let var1 := mulmod(f_37, var0, R)
                        let a_3 := calldataload(0x3384)
                        let var2 := mulmod(var1, a_3, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x61a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6184), sub(R, calldataload(0x6164)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x61c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x61c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_38 := calldataload(0x3e64)
                        let var0 := 0x1
                        let var1 := mulmod(f_38, var0, R)
                        let a_4 := calldataload(0x33a4)
                        let var2 := mulmod(var1, a_4, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6204), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x61e4), sub(R, calldataload(0x61c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6224), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6224), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_39 := calldataload(0x3e84)
                        let var0 := 0x1
                        let var1 := mulmod(f_39, var0, R)
                        let a_5 := calldataload(0x33c4)
                        let var2 := mulmod(var1, a_5, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6264), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6244), sub(R, calldataload(0x6224)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6284), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6284), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_40 := calldataload(0x3ea4)
                        let var0 := 0x1
                        let var1 := mulmod(f_40, var0, R)
                        let a_6 := calldataload(0x33e4)
                        let var2 := mulmod(var1, a_6, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x62c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x62a4), sub(R, calldataload(0x6284)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x62e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x62e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_41 := calldataload(0x3ec4)
                        let var0 := 0x1
                        let var1 := mulmod(f_41, var0, R)
                        let a_7 := calldataload(0x3404)
                        let var2 := mulmod(var1, a_7, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6324), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6304), sub(R, calldataload(0x62e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6344), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6344), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_42 := calldataload(0x3ee4)
                        let var0 := 0x1
                        let var1 := mulmod(f_42, var0, R)
                        let a_8 := calldataload(0x3424)
                        let var2 := mulmod(var1, a_8, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6384), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6364), sub(R, calldataload(0x6344)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x63a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x63a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_43 := calldataload(0x3f04)
                        let var0 := 0x1
                        let var1 := mulmod(f_43, var0, R)
                        let a_9 := calldataload(0x3444)
                        let var2 := mulmod(var1, a_9, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x63e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x63c4), sub(R, calldataload(0x63a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6404), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6404), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_44 := calldataload(0x3f24)
                        let var0 := 0x1
                        let var1 := mulmod(f_44, var0, R)
                        let a_10 := calldataload(0x3464)
                        let var2 := mulmod(var1, a_10, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6444), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6424), sub(R, calldataload(0x6404)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6464), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6464), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_45 := calldataload(0x3f44)
                        let var0 := 0x1
                        let var1 := mulmod(f_45, var0, R)
                        let a_11 := calldataload(0x3484)
                        let var2 := mulmod(var1, a_11, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x64a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6484), sub(R, calldataload(0x6464)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x64c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x64c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_46 := calldataload(0x3f64)
                        let var0 := 0x1
                        let var1 := mulmod(f_46, var0, R)
                        let a_12 := calldataload(0x34a4)
                        let var2 := mulmod(var1, a_12, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6504), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x64e4), sub(R, calldataload(0x64c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6524), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6524), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x3a24)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_47 := calldataload(0x3f84)
                        let var0 := 0x1
                        let var1 := mulmod(f_47, var0, R)
                        let a_13 := calldataload(0x34c4)
                        let var2 := mulmod(var1, a_13, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6564), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6544), sub(R, calldataload(0x6524)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6584), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6584), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_48 := calldataload(0x3fa4)
                        let var0 := 0x1
                        let var1 := mulmod(f_48, var0, R)
                        let a_0 := calldataload(0x3324)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x65c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x65a4), sub(R, calldataload(0x6584)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x65e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x65e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_49 := calldataload(0x3fc4)
                        let var0 := 0x1
                        let var1 := mulmod(f_49, var0, R)
                        let a_1 := calldataload(0x3344)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6624), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6604), sub(R, calldataload(0x65e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6644), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6644), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_50 := calldataload(0x3fe4)
                        let var0 := 0x1
                        let var1 := mulmod(f_50, var0, R)
                        let a_2 := calldataload(0x3364)
                        let var2 := mulmod(var1, a_2, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6684), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6664), sub(R, calldataload(0x6644)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x66a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x66a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_51 := calldataload(0x4004)
                        let var0 := 0x1
                        let var1 := mulmod(f_51, var0, R)
                        let a_3 := calldataload(0x3384)
                        let var2 := mulmod(var1, a_3, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x66e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x66c4), sub(R, calldataload(0x66a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6704), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6704), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_52 := calldataload(0x4024)
                        let var0 := 0x1
                        let var1 := mulmod(f_52, var0, R)
                        let a_4 := calldataload(0x33a4)
                        let var2 := mulmod(var1, a_4, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6744), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6724), sub(R, calldataload(0x6704)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6764), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6764), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_53 := calldataload(0x4044)
                        let var0 := 0x1
                        let var1 := mulmod(f_53, var0, R)
                        let a_5 := calldataload(0x33c4)
                        let var2 := mulmod(var1, a_5, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x67a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6784), sub(R, calldataload(0x6764)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x67c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x67c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_54 := calldataload(0x4064)
                        let var0 := 0x1
                        let var1 := mulmod(f_54, var0, R)
                        let a_6 := calldataload(0x33e4)
                        let var2 := mulmod(var1, a_6, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6804), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x67e4), sub(R, calldataload(0x67c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6824), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6824), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_55 := calldataload(0x4084)
                        let var0 := 0x1
                        let var1 := mulmod(f_55, var0, R)
                        let a_7 := calldataload(0x3404)
                        let var2 := mulmod(var1, a_7, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6864), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6844), sub(R, calldataload(0x6824)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6884), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6884), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_56 := calldataload(0x40a4)
                        let var0 := 0x1
                        let var1 := mulmod(f_56, var0, R)
                        let a_8 := calldataload(0x3424)
                        let var2 := mulmod(var1, a_8, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x68c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x68a4), sub(R, calldataload(0x6884)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x68e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x68e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_57 := calldataload(0x40c4)
                        let var0 := 0x1
                        let var1 := mulmod(f_57, var0, R)
                        let a_9 := calldataload(0x3444)
                        let var2 := mulmod(var1, a_9, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6924), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6904), sub(R, calldataload(0x68e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6944), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6944), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_58 := calldataload(0x40e4)
                        let var0 := 0x1
                        let var1 := mulmod(f_58, var0, R)
                        let a_10 := calldataload(0x3464)
                        let var2 := mulmod(var1, a_10, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6984), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6964), sub(R, calldataload(0x6944)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x69a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x69a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_59 := calldataload(0x4104)
                        let var0 := 0x1
                        let var1 := mulmod(f_59, var0, R)
                        let a_11 := calldataload(0x3484)
                        let var2 := mulmod(var1, a_11, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x69e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x69c4), sub(R, calldataload(0x69a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6a04), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6a04), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_60 := calldataload(0x4124)
                        let var0 := 0x1
                        let var1 := mulmod(f_60, var0, R)
                        let a_12 := calldataload(0x34a4)
                        let var2 := mulmod(var1, a_12, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6a44), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6a24), sub(R, calldataload(0x6a04)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x6a64), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x6a64), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x3a44)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_61 := calldataload(0x4144)
                        let var0 := 0x1
                        let var1 := mulmod(f_61, var0, R)
                        let a_13 := calldataload(0x34c4)
                        let var2 := mulmod(var1, a_13, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x6aa4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x6a84), sub(R, calldataload(0x6a64)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, R)
                    mstore(0x0360, x_pow_of_omega)
                    mstore(0x0340, x)
                    x_pow_of_omega := mulmod(x, omega_inv, R)
                    mstore(0x0320, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    mstore(0x0300, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x0380
                            let mptr_end := 0x0400
                            let point_mptr := 0x0300
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(R, mload(point_mptr)), R))
                    }
                    let s
                    s := mload(0x03c0)
                    mstore(0x0400, s)
                    let diff
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0420, diff)
                    mstore(0x00, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0440, diff)
                    diff := mload(0x03a0)
                    mstore(0x0460, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    mstore(0x0480, diff)
                }
                {
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x20, coeff)
                }
                {
                    let point_1 := mload(0x0320)
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := addmod(point_1, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03a0), R)
                    mstore(0x40, coeff)
                    coeff := addmod(point_2, sub(R, point_1), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x60, coeff)
                }
                {
                    let point_0 := mload(0x0300)
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_0, sub(R, point_2), R)
                    coeff := mulmod(coeff, addmod(point_0, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x0380), R)
                    mstore(0x80, coeff)
                    coeff := addmod(point_2, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_2, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_3, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_3, sub(R, point_2), R), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0xc0, coeff)
                }
                {
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_2, sub(R, point_3), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_3, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0x0100, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0120)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0420, diff_0_inv)
                    for
                        {
                            let mptr := 0x0440
                            let mptr_end := 0x04a0
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, R))
                    }
                }
                {
                    let coeff := mload(0x20)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x4624), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), R), R)
                    for
                        {
                            let mptr := 0x4c04
                            let mptr_end := 0x4624
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    for
                        {
                            let mptr := 0x4604
                            let mptr_end := 0x3984
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6aa4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6a44), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x69e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6984), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6924), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x68c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6864), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6804), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x67a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6744), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x66e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6684), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6624), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x65c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6564), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6504), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x64a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6444), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x63e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6384), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6324), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x62c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6264), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6204), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x61a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6144), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x60e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6084), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x6024), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5fc4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5f64), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5f04), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5ea4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5e44), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5de4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5d84), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5d24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5cc4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5c64), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5c04), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5ba4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5b44), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5ae4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5a84), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5a24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x59c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5964), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5904), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x58a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5844), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x57e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5784), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5724), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x56c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5664), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5604), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x55a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5544), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x54e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5484), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5424), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x53c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5364), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5304), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x52a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5244), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x51e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5184), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x5124), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x50c4), R), R)
                    for
                        {
                            let mptr := 0x38a4
                            let mptr_end := 0x3824
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x3804), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x37c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x3784), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x3744), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x3704), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x36c4), R), R)
                    for
                        {
                            let mptr := 0x3684
                            let mptr_end := 0x3304
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    mstore(0x04a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x3984), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x3824), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x3964), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x37e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x3944), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x37a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x3924), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x3764), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x3904), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x3724), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x38e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x36e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x38c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x36a4), R), R)
                    r_eval := mulmod(r_eval, mload(0x0440), R)
                    mstore(0x04c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x5024), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4fe4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x5004), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4fc4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4f84), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4fa4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4f64), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4f24), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4f44), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4f04), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4ec4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4ee4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4ea4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4e64), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4e84), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4e44), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4e04), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4e24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4de4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4da4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4dc4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4d84), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4d44), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4d64), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4d24), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4ce4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4d04), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4cc4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4c84), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4ca4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x4c64), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x4c24), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x4c44), R), R)
                    r_eval := mulmod(r_eval, mload(0x0460), R)
                    mstore(0x04e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6a64), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6a84), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6a04), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6a24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x69a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x69c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6944), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6964), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x68e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6904), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6884), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x68a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6824), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6844), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x67c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x67e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6764), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6784), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6704), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6724), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x66a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x66c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6644), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6664), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x65e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6604), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6584), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x65a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6524), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6544), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x64c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x64e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6464), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6484), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6404), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6424), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x63a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x63c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6344), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6364), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x62e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6304), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6284), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x62a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6224), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6244), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x61c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x61e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6164), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6184), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6104), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6124), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x60a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x60c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x6044), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6064), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5fe4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x6004), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5f84), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5fa4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5f24), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5f44), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5ec4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5ee4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5e64), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5e84), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5e04), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5e24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5da4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5dc4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5d44), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5d64), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5ce4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5d04), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5c84), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5ca4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5c24), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5c44), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5bc4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5be4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5b64), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5b84), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5b04), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5b24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5aa4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5ac4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5a44), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5a64), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x59e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5a04), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5984), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x59a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5924), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5944), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x58c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x58e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5864), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5884), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5804), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5824), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x57a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x57c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5744), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5764), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x56e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5704), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5684), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x56a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5624), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5644), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x55c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x55e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5564), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5584), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5504), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5524), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x54a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x54c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5444), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5464), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x53e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5404), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5384), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x53a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5324), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5344), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x52c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x52e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5264), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5284), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5204), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5224), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x51a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x51c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5144), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5164), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x50e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5104), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5084), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x50a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x5044), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x5064), R), R)
                    r_eval := mulmod(r_eval, mload(0x0480), R)
                    mstore(0x0500, r_eval)
                }
                {
                    let sum := mload(0x20)
                    mstore(0x0520, sum)
                }
                {
                    let sum := mload(0x40)
                    sum := addmod(sum, mload(0x60), R)
                    mstore(0x0540, sum)
                }
                {
                    let sum := mload(0x80)
                    sum := addmod(sum, mload(0xa0), R)
                    sum := addmod(sum, mload(0xc0), R)
                    mstore(0x0560, sum)
                }
                {
                    let sum := mload(0xe0)
                    sum := addmod(sum, mload(0x0100), R)
                    mstore(0x0580, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0x80
                            let sum_mptr := 0x0520
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x80)
                    let r_eval := mulmod(mload(0x60), mload(0x0500), R)
                    for
                        {
                            let sum_inv_mptr := 0x40
                            let sum_inv_mptr_end := 0x80
                            let r_eval_mptr := 0x04e0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), R)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), R), R)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x31a4))
                    mstore(0x20, calldataload(0x31c4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x5ee0
                            let mptr_end := 0x3a20
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x1ce4
                            let mptr_end := 0x0a64
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0x0a24), calldataload(0x0a44))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0x09a4), calldataload(0x09c4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0x0924), calldataload(0x0944))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0x08a4), calldataload(0x08c4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0x0824), calldataload(0x0844))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0x07a4), calldataload(0x07c4))
                    for
                        {
                            let mptr := 0x0724
                            let mptr_end := 0x24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    mstore(0x80, calldataload(0x0a64))
                    mstore(0xa0, calldataload(0x0a84))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x09e4), calldataload(0x0a04))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0964), calldataload(0x0984))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x08e4), calldataload(0x0904))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0864), calldataload(0x0884))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x07e4), calldataload(0x0804))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0764), calldataload(0x0784))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0440), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x1fa4))
                    mstore(0xa0, calldataload(0x1fc4))
                    for
                        {
                            let mptr := 0x1f64
                            let mptr_end := 0x1ce4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0460), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x3164))
                    mstore(0xa0, calldataload(0x3184))
                    for
                        {
                            let mptr := 0x3124
                            let mptr_end := 0x1fa4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0480), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(R, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x6ac4))
                    mstore(0xa0, calldataload(0x6ae4))
                    success := ec_mul_tmp(success, sub(R, mload(0x0400)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x6b04))
                    mstore(0xa0, calldataload(0x6b24))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x6b04))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x6b24))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}