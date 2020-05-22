/**
 *
 * @author Jianmin kong
 *
 * @date 2019年12月13日
 *
 * @target Data Trading
 */

import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Random;
import java.math.BigInteger;
import java.util.Scanner;


/**
 *
 * @author Jianmin kong
 *
 * @date from 2019.12.10-2019.12.22
 *
 * @class core
 */
public class core {
    /**
     * @function pairingGen
     * @input /
     * @ouput pairing
     * @target Generate pairing
     */
    public static Pairing pairingGen() {
        PairingParametersGenerator pg = new TypeACurveGenerator(256, 256);//指定椭圆曲线的种类
        PairingParameters params = pg.generate();//产生椭圆曲线参数
//        BigInteger p = params.getBigInteger("r");
//        Common.writeFile("/a.properties", params.toString()
//                .getBytes());
//        Out out = new Out("a.properties");
//        out.println(params);
//        Pairing pairing = PairingFactory.getPairing("a.properties");
        Pairing pairing = PairingFactory.getPairing(params);//初始化Pairing
        return pairing;
    }


    /**
     * @function generateg
     * @input /
     * @ouput pairing
     * @target Generate g, generator of G2
     */
    public static Element generateg(Pairing pairing) {
        Element g = pairing.getG1().newRandomElement().getImmutable();// 生成G1的生成元g
        return g;
    }


    /**
     * @function getx
     * @input Random random1
     * @ouput Biginteger x
     * @target Get x and x’，x is sk
     */
    public static BigInteger getx(Random random1) {
        BigInteger x = new BigInteger(16, 1000, random1); //私钥x，卖家
        return x;
    }

    /**
     * @function getC1
     * @input Element g,BigInteger r
     * @ouput Element C1
     * @target Get C1，C1 is calculated from g and r
     */
    public static Element pow_operation(Element g, Element r) {
        Element C1 = g.duplicate().powZn(r).getImmutable();//C1=g^r卖家
        return C1;
    }


    /**
     * @function hashToG2
     * @input Pairing pairing,byte[] sha256_C1
     * @ouput Element HC1
     * @target Get HC1，HC1 is C1 hash to a point in G2
     */
    public static Element hashToG2(Pairing pairing, byte[] sha256_C1) {
        Element HC1 = pairing.getG2().newElement().setFromHash(sha256_C1, 0, sha256_C1.length).getImmutable();//将byte[] sha256_C1哈希到G2群  H(C1)
        return HC1;
    }


    /**
     * @function Encrypt
     * @input Pairing pairing,Element y, BigInteger r, Element HC1, BigInteger m
     * @ouput C2
     * @target Encrypt m
     */
    //加密
    public static Element Encrypt(Pairing pairing, Element y, Element r, Element HC1, BigInteger m) {
        Element C2 = pairing.pairing(y.duplicate().powZn(r), HC1).duplicate().mul(m).getImmutable();//m加密后C2
        return C2;
    }


    /**
     * @function Decrypt
     * @input Pairing pairing,Element C1, Element HC1, Element C2,BigInteger x,BigInteger p,BigInteger m
     * @ouput m_decrypt
     * @target Decrypt m
     */

    public static BigInteger Decrypt(Pairing pairing, Element C1, Element C2, Element x2, BigInteger p, Element A) {
        Element HC1_x = pow_operation(A.getImmutable(), x2.invert()).getImmutable();
        Element C2_div_e = C2.div(getPairing(pairing, C1.getImmutable(), HC1_x.getImmutable())).getImmutable();
        BigInteger mxx = C2_div_e.toBigInteger().mod(p);
        return mxx;
    }

    /**
     * @function getPairing
     * @input Pairing pairing,Element y, Element R
     * @ouput e
     * @target get e(y,R) or e(g,A)
     */
    public static Element getPairing(Pairing pairing, Element y, Element R) {
        Element e = pairing.pairing(y, R).getImmutable();
        return e;
    }


    /**
     * @function sha256
     * @input byte[] data
     * @ouput hash
     * @target SHA256 operation
     */
    public static byte[] sha256(byte[] data) {
        SHA256Digest dgst = new SHA256Digest();
        dgst.reset();
        dgst.update(data, 0, data.length);
        int digestSize = dgst.getDigestSize();
        byte[] hash = new byte[digestSize];
        dgst.doFinal(hash, 0);
        return hash;
    }


    /**
     * @function exGcd
     * @input BigInteger a, BigInteger b
     * @ouput arr(Inverse element for a and b)
     * @target Extended Euclidean Algorithm for Inverse Elements of Module a and b
     */
    //扩展欧几里得算法求a模b的逆元
    public static BigInteger[] exGcd(BigInteger a, BigInteger b) {
        if (b == BigInteger.ZERO) {
            BigInteger[] arr = new BigInteger[]{BigInteger.ONE, BigInteger.ZERO};
            return arr;
        } else {
            BigInteger[] arr = exGcd(b, a.mod(b));
            BigInteger x = arr[0];
            arr[0] = arr[1];
            arr[1] = x.subtract(a.divide(b)).multiply(arr[1]);
            return arr;
        }
    }


    /**
     * @function isEqual
     * @input Element data1,Element data2
     * @ouput true or false
     * @target Judging data1 and data2 is equal or not
     */
    //判断e(y,R)是否等于e(g,A)
    public static boolean isEqual(Element data1, Element data2) {
        if (data1.equals(data2)) {
            return true;
        } else {
            return false;
        }
    }


    /**
     * @function Timer
     * @target Record running time of the programs
     */
    public static class Timer {
        private long startTime = System.currentTimeMillis();

        public void reset() {
            startTime = System.currentTimeMillis();
        }

        public int lap() {
            return (int) (System.currentTimeMillis() - startTime);
        }
    }


    /**
     * @function eTostring
     * @input Element e
     * @ouput String e_string
     * @target Makeing e to String , store in the solidity contract
     */
    public static String eTostring(Element e) {
        byte[] bytes = e.toBytes();//首先把e转成bytes数组
        String e_string = Base64v2.encode(bytes);
        return e_string;
    }


    /**
     * @function stringToe
     *
     * @input String e_string,Element g
     * @ouput Element e
     * @target Taking string from solidity,then someone transforms it to
     */
//    public static  Element stringToe(String e_string,Element g){
//        byte[] bytes = Base64v2.decode(e_string,false);
//        Element e = gety(g,BigInteger.valueOf(5));
//        int bytesRead = e.setFromBytes(bytes);
//        return e;
//    }


    /**
     * Convert an array of bytes into a String
     *
     * @param input An array of bytes in UTF-8 format
     * @return The converted String
     */
    public static String bytesToString(byte[] input) {
        String output = null;
        try {
            output = new String(input, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            output = new String(input);
        }
        return output;
    }


    public static byte[] toByteArray(BigInteger bi) {
        byte[] array = bi.toByteArray();
        if (array[0] == 0) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        return array;
    }

    public static void main(String[] args) {


//        Scanner input=new Scanner(System.in);
//        System.out.println("请输入商品明文信息：");
//        BigInteger m = input.nextBigInteger();//m为商品明文信息
        BigInteger m = new BigInteger(String.valueOf(5));
        long ESS = 0;


        //************** SellerPrep *********//
        PairingParametersGenerator pg = new TypeACurveGenerator(128, 256);//指定椭圆曲线的种类
        PairingParameters params = pg.generate();//产生椭圆曲线参数
        BigInteger q = params.getBigInteger("q");
        BigInteger rr = params.getBigInteger("r");
//        Common.writeFile("/a.properties", params.toString()
//                .getBytes());
//        Out out = new Out("a.properties");
//        out.println(params);
//        Pairing pairing = PairingFactory.getPairing("a.properties");
        Pairing pairing = PairingFactory.getPairing(params);//初始化Pairing
        // Pairing pairing = pairingGen();//初始化pairing
        Element g = generateg(pairing).getImmutable();// 生成G1的生成元g(不可变）
        Random random1 = new Random();



        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element y = pow_operation(g.duplicate(), x.duplicate()).getImmutable();
        Element C1 = pow_operation(g.duplicate(), r.duplicate()).getImmutable();//C1=g^r卖家
        byte[] sha256_C1 = sha256(C1.duplicate().toBytes());
        Element HC1 = hashToG2(pairing, sha256_C1).getImmutable();

        Element C2 = Encrypt(pairing, y, r, HC1, m).getImmutable();//m加密后C2
        System.out.println("加密后明文为:" + C2.getImmutable());
        System.out.println("x:" + x);
        System.out.println("r:" + r);
        System.out.println("q:" + q);
        System.out.println("rr:" + rr);
        //************** SellerPrep *********//


        //************** BuyerPrep *********//

        long startTime2 = System.nanoTime();   //获取开始时间
        byte[] sha256_C1_x2 = sha256(C1.duplicate().toBytes());
        Element HC1_x2 = hashToG2(pairing, sha256_C1).getImmutable();
        Element x2 = pairing.getZr().newRandomElement().getImmutable();
        Element y2 = pow_operation(g, x2).getImmutable();

        Element R = pow_operation(HC1, x2).getImmutable();//买家
        Element e_y2_HC1 = getPairing(pairing, y2, HC1);//买家
        Element e_g_R = getPairing(pairing, g, R);//买家
        if (isEqual(e_y2_HC1, e_g_R)) {
            System.out.println("验证成功！");
        }
        System.out.println("x2:" + x2);
        System.out.println("y2:" + y2);
        System.out.println("R:" + R.getImmutable());
        // ************** BuyerPrep *********//

        //************** SendInfo *********//
        Element A = pow_operation(R.getImmutable(), x).getImmutable();//卖家
        //************** SendInfo *********//

        Element e_y_R = getPairing(pairing, y, R);//买家
        Element e_g_A = getPairing(pairing, g, A);//卖家

        //************** Decrypt *********//
        BigInteger Decrypt_m = Decrypt(pairing, C1.getImmutable(), C2.getImmutable(), x2.getImmutable(), q, A.getImmutable());


        //************** Decrypt *********//


        System.out.println("g:" +g);
        System.out.println("y:" +y);
        System.out.println();

        System.out.println("c1:" + C1);
        System.out.println("c2:" + C2);
        System.out.println("HC1:" + HC1);
        System.out.println("R:" +R);
        System.out.println("A:" +A);
        System.out.println("e(y,R):" +e_y_R);//e(y,R)


        System.out.println(Base64v2.encode(e_y_R.toBytes()));
        System.out.println(Base64v2.encode(e_y_R.toBytes()).length());
        System.out.println("e(g,A):" +e_g_A);//e(g,A)


        String y_string = eTostring(y);
        System.out.println("y_string:" + y_string);
        System.out.println("y2:" + eTostring(y2));
        System.out.println("HC1_string:" + eTostring(HC1));
        System.out.println("x:" + x);
//        System.out.println("sha256_x:" + Base64v2.encode((sha256((toByteArray(x))))));
//        System.out.println("sha256_x.lenth:" + Base64v2.encode((sha256((toByteArray(x))))).length());

        System.out.println("R_string:" + eTostring(R));
        System.out.println("e_y_R_string:" + eTostring(e_y_R));
        System.out.println("e_g_A_string:" + eTostring(e_g_A));
        System.out.println("g_string:" + eTostring(g));
        System.out.println("A_string:" + eTostring(A));

//        Element y_e = stringToe(y_string,g);
//        System.out.println("y_e:" + y_e);

        byte[] bytes = e_g_A.toBytes();
        System.out.println("bytes：" + bytes);
        System.out.println("Arrays：" + Arrays.toString(bytes));
        System.out.println("bytes_string:" + Base64v2.encode(bytes));
        System.out.println("decodeArrays:" + Arrays.toString(Base64v2.decode(Base64v2.encode(bytes),true)));


        byte[] bytes1 = e_g_A.toBytes();
        System.out.println("bytes1：" + bytes1);
        System.out.println("Arrays：" + Arrays.toString(bytes1));
        System.out.println("bytes1_string:" + Base64v2.encode(bytes1));
        System.out.println("decodeArrays:" + Arrays.toString(Base64v2.decode(Base64v2.encode(bytes1),true)));


        Element eee = y;
        Element aaa = C1;
//        int bytesRead = eee.setFromBytes(bytes);
//        int bytesRead2 = aaa.setFromBytes(bytes1);
//        System.out.println(eee);
//        System.out.println(aaa);

        if(isEqual(e_y_R,e_g_A)) {
       System.out.println("验证成功！");
       }

        else
       System.out.println("验证失败！");

       }
      }
