use bulletproof::proofs::range_proof::RangeProof;
use curv::arithmetic::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::secp256_k1::hash_to_curve::generate_random_point;
use curv::elliptic::curves::*;
use sha2::{Sha256, Sha512};
use std::{mem, time};

const SECURITY_BITS: usize = 256;
const RANGE_SIZE: usize = 9;
const BATCH_SIZE: usize = 2;
const SEEDS: &[u8] = &[75, 90, 101, 110];

pub struct ElgamalCipher<E: Curve> {
    pub c1: Point<E>,
    pub c2: Point<E>,
}

pub struct ElgamalCompressCipher<E: Curve> {
    pub c1: Point<E>, //r1 * g
    pub c2: Point<E>, //val * g + r1 * pk_reg
    pub c3: Point<E>, //val * g + r1 * pk_i
    pub c4: Point<E>, //val * g + r1 * pk_j
}

pub struct ElgamalDecShare<E: Curve> {
    pub share: Point<E>,
    pub index: i32,
}

pub struct CbpsTx<E: Curve> {
    pub ct_reg: ElgamalCipher<E>,
    pub emp_enc_to: ElgamalCipher<E>,
    pub emp_enc_from: ElgamalCipher<E>,
    pub sig_pf_to: SigmaPf<E>,
    pub sig_pf_reg: SigmaPf<E>,
    pub sig_pf_from: SigmaPf<E>,
    pub range_pf_reg: RangeProof,
}

pub struct CBPSTx<E: Curve> {
    pub from: Point<E>,
    pub to: Point<E>,
    pub compressed_e: ElgamalCompressCipher<E>,
    pub new_r_bal_i: ElgamalCipher<E>,
    pub pc_bal: Point<E>,
    pub pi_eq: PiEq<E>,
    pub pi_bal_r: PiBalR<E>,
    pub pi_bal_k: PiBalK<E>,
    pub batch_range_pf: RangeProof,
}

pub struct SigmaPf<E: Curve> {
    pub r1: Scalar<E>,
    pub r2: Scalar<E>,
    pub r3: Point<E>,
    pub r4: Point<E>,
}

pub struct PiEq<E: Curve> {
    pub e1: Point<E>,
    pub e2: Point<E>,
    pub e4: Point<E>,
    pub e6: Point<E>,
    pub t1: Scalar<E>,
    pub t4: Scalar<E>,
}

pub struct PiBalR<E: Curve> {
    pub e7: Point<E>,
    pub t5: Scalar<E>,
}

pub struct PiBalK<E: Curve> {
    pub e8: Point<E>,
    pub e9: Point<E>,
    pub t6: Scalar<E>,
    pub t7: Scalar<E>,
}

pub fn central_gen_thresh_key<E: Curve>(t: i32, n: i32) -> (Point<E>, Vec<Scalar<E>>) {
    let mut sks = Vec::new();
    let mut par = Vec::new();
    let g = Point::<E>::generator();
    for _ in 0..t {
        par.push(Scalar::<E>::random());
    }
    for i in 1..n + 1 {
        let r = eval_function(&par, i.into());
        sks.push(r);
    }
    (&par[0] * g, sks)
}

fn eval_function<E: Curve>(func_par: &[Scalar<E>], n: Scalar<E>) -> Scalar<E> {
    let mut result = BigInt::zero();
    let n_bigint = n.to_bigint();
    for (i, par) in func_par.iter().enumerate() {
        result += n_bigint.pow(i.try_into().unwrap()) * par.to_bigint();
    }
    Scalar::<E>::from_bigint(&result)
}

pub fn gen_key<E: Curve>() -> (Point<E>, Scalar<E>) {
    let g = Point::<E>::generator();
    let x = BigInt::sample(SECURITY_BITS);
    let x_scalar = Scalar::<E>::from(x);
    (&x_scalar * g, x_scalar)
}

pub fn commit<E: Curve>(message: &Scalar<E>, key: &Point<E>, random: &Scalar<E>) -> Point<E> {
    let g = Point::<E>::generator();
    let mg = message * g;
    let rk = random * key;
    let c2 = mg + rk;

    c2
}

pub fn elgamal_enc<E: Curve>(
    message: &Scalar<E>,
    pk: &Point<E>,
    em_key: &Scalar<E>,
) -> ElgamalCipher<E> {
    let g = Point::<E>::generator();
    // let k = BigInt::sample(SECURITY_BITS);
    // let k_scalar = Scalar::<E>::from(k);
    let c1 = em_key * g;
    let mg = message * g;
    let kp = em_key * pk;
    let c2 = mg + kp;
    ElgamalCipher { c1, c2 }
}

//Encrypt val in with three pks
pub fn comp_elgamal_enc<E: Curve>(
    val: &Scalar<E>,
    pk_reg: &Point<E>,
    pk_i: &Point<E>,
    pk_j: &Point<E>,
    em_key: &Scalar<E>,
) -> ElgamalCompressCipher<E> {
    let g = Point::<E>::generator();
    //c1
    let c1 = em_key * g;
    let mg = val * g;
    //c2
    let rpkr = em_key * pk_reg;
    let c2 = &mg + rpkr;
    //c3
    let rpki = em_key * pk_i;
    let c3 = &mg + rpki;
    //c4
    let rpkj = em_key * pk_j;
    let c4 = &mg + rpkj;

    ElgamalCompressCipher { c1, c2, c3, c4 }
}

pub fn elgamal_add<E: Curve>(ct1: &ElgamalCipher<E>, ct2: &ElgamalCipher<E>) -> ElgamalCipher<E> {
    let new_c1 = &ct1.c1 + &ct2.c1;
    let new_c2 = &ct1.c2 + &ct2.c2;
    ElgamalCipher {
        c1: new_c1,
        c2: new_c2,
    }
}

pub fn elgamal_sub<E: Curve>(ct1: &ElgamalCipher<E>, ct2: &ElgamalCipher<E>) -> ElgamalCipher<E> {
    let new_c1 = &ct1.c1 - &ct2.c1;
    let new_c2 = &ct1.c2 - &ct2.c2;
    ElgamalCipher {
        c1: new_c1,
        c2: new_c2,
    }
}

pub fn elgamal_dec_share<E: Curve>(
    ct: &ElgamalCipher<E>,
    sk_share: &Scalar<E>,
    index: i32,
) -> ElgamalDecShare<E> {
    let share = sk_share * &ct.c1;
    ElgamalDecShare { share, index }
}

pub fn combind_share<E: Curve>(
    ct: &ElgamalCipher<E>,
    shares: &[ElgamalDecShare<E>],
) -> Result<Scalar<E>, ()> {
    let indices: Vec<f64> = shares.iter().map(|share| share.index as f64).collect();
    let mut res_ct = Point::<E>::zero();
    for share in shares {
        let mut inter = 1f64;
        for j in &indices {
            if j == &(share.index as f64) {
                continue;
            }
            inter *= j / (j - &(share.index as f64));
        }
        let a = Scalar::<E>::from(inter as i32) * &share.share;
        res_ct = res_ct + a;
    }
    let result = &ct.c2 - res_ct;
    let g = Point::<E>::generator();
    for i in 1..10000001 {
        let i_scalar = Scalar::<E>::from(i as i32);
        if &i_scalar * g == result {
            return Ok(i_scalar);
        }
    }
    Err(())
}

pub fn elgamal_dec<E: Curve>(ct: &ElgamalCipher<E>, sk: &Scalar<E>) -> Result<Scalar<E>, ()> {
    let m_xc1 = -sk * &ct.c1;
    let mg = &m_xc1 + &ct.c2;
    let g = Point::<E>::generator();
    for i in 1..1000 {
        let i_scalar = Scalar::<E>::from(i);
        if &i_scalar * g == mg {
            return Ok(i_scalar);
        }
    }
    Err(())
}

//Generate sigma protocol zk-proof pi_eq for compressed elgamal
pub fn gen_proof_pieq<E: Curve>(
    r1: &Scalar<E>,
    value: &Scalar<E>,
    pk_reg: &Point<E>,
    pk_i: &Point<E>,
    pk_j: &Point<E>,
    g: &Point<E>,
) -> PiEq<E> {
    //Generate random number
    let k1 = Scalar::<E>::random();
    let k4 = Scalar::<E>::random();

    //Generate e inside the pf
    let e1 = &k1 * g;
    let e2 = &k4 * g + &k1 * pk_reg;
    let e4 = &k4 * g + &k1 * pk_i;
    let e6 = &k4 * g + &k1 * pk_j;

    //Generate challenge c
    let c = Sha512::new()
        .chain_point(g)
        .chain_point(pk_reg)
        .chain_point(pk_i)
        .chain_point(pk_j)
        .chain_point(&e1)
        .chain_point(&e2)
        .chain_point(&e4)
        .chain_point(&e6)
        .result_scalar::<E>();

    //Generate response
    let t1 = &k1 + (&c * r1);
    let t4 = &k4 + (&c * value);

    PiEq {
        e1,
        e2,
        e4,
        e6,
        t1,
        t4,
    }
}

//Verify Pi_eq sigma pf
pub fn verify_pieq<E: Curve>(
    ct: &ElgamalCompressCipher<E>,
    pf: &PiEq<E>,
    pk_reg: &Point<E>,
    pk_i: &Point<E>,
    pk_j: &Point<E>,
    g: &Point<E>,
) -> Result<(), ()> {
    //Generate challenge c
    let c = Sha512::new()
        .chain_point(g)
        .chain_point(pk_reg)
        .chain_point(pk_i)
        .chain_point(pk_j)
        .chain_point(&pf.e1)
        .chain_point(&pf.e2)
        .chain_point(&pf.e4)
        .chain_point(&pf.e6)
        .result_scalar::<E>();

    if &pf.t1 * g != &pf.e1 + (&c * &ct.c1) {
        return Err(());
    }
    if &pf.t4 * g + &pf.t1 * pk_reg != &pf.e2 + (&c * &ct.c2) {
        return Err(());
    }
    if &pf.t4 * g + &pf.t1 * pk_i != &pf.e4 + (&c * &ct.c3) {
        return Err(());
    }
    if &pf.t4 * g + &pf.t1 * pk_j != &pf.e6 + (&c * &ct.c4) {
        return Err(());
    }

    Ok(())
}

pub fn gen_proof_pibal_r<E: Curve>(
    new_bal_i: &ElgamalCipher<E>,
    new_r_bal_i: &ElgamalCipher<E>,
    sk_i: &Scalar<E>,
) -> PiBalR<E> {
    let x = &new_bal_i.c1 - &new_r_bal_i.c1;
    let y = &new_bal_i.c2 - &new_r_bal_i.c2;
    //Generate random number
    let k5 = Scalar::<E>::random();
    //Generate e in pf
    let e7 = &k5 * &x;
    //Generate challenge c
    let c = Sha256::new()
        .chain_point(&x)
        .chain_point(&y)
        .chain_point(&e7)
        .result_scalar::<E>();
    //Generate response
    let t5 = &k5 + &c * sk_i;

    PiBalR { e7, t5 }
}

pub fn verify_pibal_r<E: Curve>(
    new_bal_i: &ElgamalCipher<E>,
    new_r_bal_i: &ElgamalCipher<E>,
    pf: &PiBalR<E>,
) -> Result<(), ()> {
    let x = &new_bal_i.c1 - &new_r_bal_i.c1;
    let y = &new_bal_i.c2 - &new_r_bal_i.c2;

    //Generate challenge c
    let c = Sha256::new()
        .chain_point(&x)
        .chain_point(&y)
        .chain_point(&pf.e7)
        .result_scalar::<E>();

    if &pf.t5 * x != &pf.e7 + c * y {
        return Err(());
    }

    Ok(())
}

pub fn gen_proof_pibal_k<E: Curve>(
    g: &Point<E>,
    pk_i: &Point<E>,
    pk_reg: &Point<E>,
    pt_new_bal_i: &Scalar<E>,
    new_rand: &Scalar<E>,
) -> PiBalK<E> {
    //Generate random number
    let k6 = Scalar::<E>::random();
    let k7 = Scalar::<E>::random();
    //Generate e in pf
    let k6g = &k6 * g;
    let e8 = &k6g + &k7 * pk_i;
    let e9 = &k6g + &k7 * pk_reg;
    //Generate challenge c
    let c = Sha256::new()
        .chain_point(g)
        .chain_point(pk_i)
        .chain_point(pk_reg)
        .chain_point(&e8)
        .chain_point(&e9)
        .result_scalar::<E>();
    //Generate response
    let t6 = &k6 + &c * pt_new_bal_i;
    let t7 = &k7 + &c * new_rand;

    PiBalK { e8, e9, t6, t7 }
}

pub fn verify_pibal_k<E: Curve>(
    g: &Point<E>,
    pk_i: &Point<E>,
    pk_reg: &Point<E>,
    pc_bal: &Point<E>,
    new_r_bal_i_2: &Point<E>,
    pf: &PiBalK<E>,
) -> Result<(), ()> {
    //Generate challenge c
    let c = Sha256::new()
        .chain_point(g)
        .chain_point(pk_i)
        .chain_point(pk_reg)
        .chain_point(&pf.e8)
        .chain_point(&pf.e9)
        .result_scalar::<E>();
    if &pf.t6 * g + &pf.t7 * pk_i != &pf.e8 + &c * new_r_bal_i_2 {
        return Err(());
    }
    if &pf.t6 * g + &pf.t7 * pk_reg != &pf.e9 + &c * pc_bal {
        return Err(());
    }
    Ok(())
}

fn gen_tx(
    pk_i: &Point<Secp256k1>,
    sk_i: &Scalar<Secp256k1>,
    pk_j: &Point<Secp256k1>,
    pk_reg: &Point<Secp256k1>,
    value: &BigInt,
    g_vec: &Vec<Point<Secp256k1>>,
    h_vec: &Vec<Point<Secp256k1>>,
    n: usize,
    bal_i: &Scalar<Secp256k1>,
    renc_bal_i: &ElgamalCipher<Secp256k1>,
    uenc_bal_i: &ElgamalCipher<Secp256k1>,
) -> CBPSTx<Secp256k1> {
    let g = Point::<Secp256k1>::generator();
    let v_scalar = Scalar::<Secp256k1>::from(value);
    let r1 = Scalar::<Secp256k1>::random();
    let comp_elgamal = comp_elgamal_enc(&v_scalar, pk_reg, pk_i, pk_j, &r1);
    let pf_pieq = gen_proof_pieq(&r1, &v_scalar, pk_reg, pk_i, pk_j, &g); //gen pi_eq

    let eusr_i = ElgamalCipher::<Secp256k1> {
        c1: comp_elgamal.c1.clone(),
        c2: comp_elgamal.c3.clone(),
    };
    let new_rand = Scalar::<Secp256k1>::random();
    let pt_new_bal_i = bal_i - &v_scalar;
    let new_bal_i = elgamal_sub(uenc_bal_i, &eusr_i); //calculate balance after tx
    let new_r_bal_i = elgamal_enc(&pt_new_bal_i, pk_i, &new_rand); //generate encrypted val with new random
    let pf_pibal_r = gen_proof_pibal_r(&new_bal_i, &new_r_bal_i, sk_i); //gen pi_bal_r

    let pc_bal = commit(&pt_new_bal_i, pk_reg, &new_rand); //commitment for range pf
    let pf_pibal_k = gen_proof_pibal_k(&g, pk_i, pk_reg, &pt_new_bal_i, &new_rand); // gen pi_bal_k

    //batch pi_range and pi_bal
    let scalars = vec![v_scalar, pt_new_bal_i];
    let keys = vec![r1, new_rand];
    let pf_range_batch = RangeProof::prove(g_vec, h_vec, &g, pk_reg, scalars, &keys, n);
    CBPSTx {
        from: pk_i.clone(),
        to: pk_j.clone(),
        compressed_e: comp_elgamal,
        new_r_bal_i: new_r_bal_i,
        pc_bal: pc_bal,
        pi_eq: pf_pieq,
        pi_bal_r: pf_pibal_r,
        pi_bal_k: pf_pibal_k,
        batch_range_pf: pf_range_batch,
    }
}

pub fn verify_tx(
    tx: &CBPSTx<Secp256k1>,
    pk_reg: &Point<Secp256k1>,
    g_vec: &Vec<Point<Secp256k1>>,
    h_vec: &Vec<Point<Secp256k1>>,
    n: usize,
    uenc_bal_i: &ElgamalCipher<Secp256k1>,
) -> Result<(), ()> {
    let g = Point::<Secp256k1>::generator();
    let res = verify_pieq(&tx.compressed_e, &tx.pi_eq, pk_reg, &tx.from, &tx.to, &g);
    match res {
        Ok(()) => print!("OK"),
        Err(()) => println!("Err!"),
    }

    let eusr_i = ElgamalCipher::<Secp256k1> {
        c1: tx.compressed_e.c1.clone(),
        c2: tx.compressed_e.c3.clone(),
    };
    let new_bal_i = elgamal_sub(uenc_bal_i, &eusr_i); //calculate balance after tx
    let res = verify_pibal_r(&new_bal_i, &tx.new_r_bal_i, &tx.pi_bal_r);
    match res {
        Ok(()) => print!("OK"),
        Err(()) => println!("Err!"),
    }
    let res = verify_pibal_k(
        &g,
        &tx.from,
        pk_reg,
        &tx.pc_bal,
        &tx.new_r_bal_i.c2,
        &tx.pi_bal_k,
    );
    match res {
        Ok(()) => print!("OK"),
        Err(()) => println!("Err!"),
    }
    let ped_coms = &[tx.compressed_e.c2.clone(), tx.pc_bal.clone()];
    let res = RangeProof::verify(&tx.batch_range_pf, g_vec, h_vec, &g, &pk_reg, ped_coms, n);
    match res {
        Ok(()) => print!("OK"),
        Err(er) => println!("{:?}", er),
    }

    Ok(())
}

fn main() {
    // bit range
    let n = 64;
    // batch size
    let m = 2;
    let nm = n * m;
    //seeds
    let seeds: &[u8] = &[75, 90, 101, 110];
    let seeds_label = BigInt::from_bytes(seeds);

    let g_vec = (0..nm)
        .map(|i| {
            let kzen_label_i = BigInt::from(i as u32) + &seeds_label;
            let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
            generate_random_point(&Converter::to_bytes(&hash_i))
        })
        .collect::<Vec<Point<Secp256k1>>>();

    let h_vec = (0..nm)
        .map(|i| {
            let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &seeds_label;
            let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
            generate_random_point(&Converter::to_bytes(&hash_j))
        })
        .collect::<Vec<Point<Secp256k1>>>();

    let (pk_i, sk_i) = gen_key::<Secp256k1>();
    let (pk_j, sk_j) = gen_key::<Secp256k1>();
    let (pk_reg, sks_reg) = central_gen_thresh_key::<Secp256k1>(3, 5);

    let value = BigInt::from(100i32);
    // let now = time::Instant::now();

    //balance of usr_i
    let r1 = Scalar::<Secp256k1>::random();
    let r2 = Scalar::<Secp256k1>::random();
    let bal_i = Scalar::<Secp256k1>::from(500i32);
    let renc_bal_i = elgamal_enc(&bal_i, &pk_reg, &r1);
    let uenc_bal_i = elgamal_enc(&bal_i, &pk_i, &r2);

    //balance of usr_j
    let r1 = Scalar::<Secp256k1>::random();
    let r2 = Scalar::<Secp256k1>::random();
    let bal_j = Scalar::<Secp256k1>::from(300i32);
    let renc_bal_j = elgamal_enc(&bal_j, &pk_reg, &r1);
    let uenc_bal_j = elgamal_enc(&bal_j, &pk_j, &r2);

    let tx = gen_tx(
        &pk_i,
        &sk_i,
        &pk_j,
        &pk_reg,
        &value,
        &g_vec,
        &h_vec,
        n,
        &bal_i,
        &renc_bal_i,
        &uenc_bal_i,
    );

    verify_tx(&tx, &pk_reg, &g_vec, &h_vec, n, &uenc_bal_i);
    // let tx = gen_example_tx(
    //     &pk_a,
    //     &sk_a,
    //     &pk_b,
    //     &pk_reg,
    //     value,
    //     &g_vec,
    //     &h_vec,
    //     n.clone(),
    // );
    // let elaspe = now.elapsed();

    // println!("Size of tx: {}", mem::size_of_val(&tx));
    // println!("Time of gen tx: {}", elaspe.as_secs_f32());

    // let now = time::Instant::now();
    // let r = verify_tx(tx, &pk_reg, &g_vec, &h_vec, n);
    // let elaspe = now.elapsed();
    // println!("Time of ver tx: {}", elaspe.as_secs_f32());

    // let tx: CbpsTx<Secp256k1>;
    // match r {
    //     Ok(tx1) => {
    //         tx = tx1;
    //         println!("OK!");
    //     }
    //     Err(()) => {
    //         println!("ERROR");
    //         return;
    //     }
    // }

    // let now = time::Instant::now();
    // let share1 = elgamal_dec_share(&tx.ct_reg, &sks_reg[0], 1);
    // let elaspe = now.elapsed();
    // println!("Time of calculate share: {}", elaspe.as_secs_f32());
    // let share2 = elgamal_dec_share(&tx.ct_reg, &sks_reg[1], 2);
    // let share3 = elgamal_dec_share(&tx.ct_reg, &sks_reg[2], 3);
    // let shares = &[share1, share2, share3];

    //==================================================================
    // let r = combind_share(&tx.ct_reg, shares).unwrap();
    // let big_r = r.to_bigint();
    // let elaspe = now.elapsed();
    // println!("{}", big_r);
    // println!("Time of dec tx: {}", elaspe.as_secs_f32());

    // let m_scalar2 = Scalar::<Secp256k1>::from(50);
    // let k2 = BigInt::sample(SECURITY_BITS);
    // let k_scalar2 = Scalar::<Secp256k1>::from(k2);
    // let ct2 = elgamal_enc(&m_scalar2, &pk, &k_scalar2);

    // let scalars = vec![m_scalar, m_scalar2];
    // let keys = vec![k_scalar, k_scalar2];

    // let range_proof = RangeProof::prove(&g_vec, &h_vec, &g, &pk, scalars, &keys, n);

    // let c2s = vec![ct.c2, ct2.c2];
    // let result = RangeProof::verify(&range_proof, &g_vec, &h_vec, &g, &pk, &c2s, n);

    // match result {
    //     Ok(_) => println!("Valid"),
    //     Err(_) => println!("Invalid"),
    // }

    // println!("{} + {} = {}", big_r, big_r2, big_r3);
    // let (pk, sk) = gen_key::<Secp256k1>();
    // let (pk_reg, sk_reg) = gen_key::<Secp256k1>();
    // let m_scalar = Scalar::<Secp256k1>::from(103i32);
    // let k = BigInt::sample(SECURITY_BITS);
    // let k_scalar = Scalar::<Secp256k1>::from(k);
    // let ct = elgamal_enc(&m_scalar, &pk_reg, &k_scalar);
    // let sig_pf = sigma_proof(&k_scalar, &m_scalar, &pk_reg);
    // let res = sigma_var(sig_pf, ct, &pk_reg);
    // match res {
    //     Ok(_) => println!("Valid"),
    //     Err(_) => println!("Invalid"),
    // }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_eval_function() {
        //f(x) = 2+3x^1+4x^2
        // let pars = &[
        //     Scalar::<Secp256k1>::from(2i32),
        //     Scalar::<Secp256k1>::from(3i32),
        //     Scalar::<Secp256k1>::from(4i32),
        // ];

        //f(3) = 47
        // let result = eval_function(pars, 3i32.into());
        // assert_eq!(Scalar::<Secp256k1>::from(47i32), result);

        //f(10) = 432
        // let result = eval_function(pars, 10i32.into());
        // assert_eq!(Scalar::<Secp256k1>::from(432i32), result);
        let s = Scalar::<Secp256k1>::from(100i32);
        let g = Point::<Secp256k1>::generator();
        let sg = &s * g;
        println!("Size of scalar: {}", mem::size_of_val(&s));
        println!("Size of point: {}", mem::size_of_val(&sg));
    }
    #[test]
    fn test_elgamal_dec() {
        let (pk_i, sk_i) = gen_key::<Secp256k1>();
        let r = Scalar::<Secp256k1>::from(100i32);
        let m1 = Scalar::<Secp256k1>::from(100i32);
        let m2 = Scalar::<Secp256k1>::from(150i32);
        let ct1 = elgamal_enc(&m1, &pk_i, &r);
        let ct2 = elgamal_enc(&m2, &pk_i, &r);
        let ct3 = elgamal_sub(&ct2, &ct1);
        let v = elgamal_dec(&ct3, &sk_i).unwrap();
        println!("{:?}", v.to_bigint())
    }
}
