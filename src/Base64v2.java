import java.io.UnsupportedEncodingException;

public  class Base64v2 {
    /**
     * Encode an array of bytes into a base64v2 String.<br><br>
     * Standard base64 uses "+" and "/" which aren't URL friendly.<br>
     * I changed them to "-" and "_" to make it URL and file friendly.<br>
     * I also changed the order so that the output is naturally sortable.
     *
     * @param input The array of bytes to encode
     *
     * @return The base64v2 String
     */
    public static String encode(byte[] input) {
        char[] lookupTable = {
                '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', // 0-15
                'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', // 16-31
                'V', 'W', 'X', 'Y', 'Z', '_', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', // 32-47
                'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'  // 48-63
        }; // 1 char = 6 bits, 4 chars = 3 bytes (24 bits)

        int inLen = input.length;
        int outLen = inLen + ((inLen + 2) / 3), outPos = 0;
        char output[] = new char[outLen];
        int bytePosition = 0, buffer = 0, bitLength = 0, bitShift;
        while (bytePosition < inLen) {
            if (bitLength < 6) { // load more bits if needed
                buffer = (buffer << 8) | (input[bytePosition++] & 0xff);
                bitLength += 8;
            }
            bitShift = bitLength - 6; // number of bits to shift the mask
            output[outPos++] = lookupTable[((0x3f << bitShift) & buffer) >> bitShift]; // append the character to the output
            bitLength -= 6;
        }
        if (bitLength > 0) { // append any remaining bits
            buffer <<= 6 - bitLength; // if <bit position> is less than 6, append zeros
            output[outPos] = lookupTable[buffer & 0x3f];
        }
        return new String(output);
    }


    /**
     * Encode a String into a base64v2 String.<br><br>
     * Standard base64 uses "+" and "/" which aren't URL friendly.<br>
     * I changed them to "-" and "_" to make it URL and file friendly.<br>
     * I also changed the order so that the output is naturally sortable.
     *
     * @param input The String to encode
     *
     * @return The base64v2 String
     */
    public static String encode(String input) {
        return encode(input.getBytes());
    }

    /**
     * Decode a base64v2 String into an array of bytes.<br>
     *
     * @param input The String to decode
     * @param dirty True if the data may contain non-base64v2 characters (ie: white space, padding)
     *
     * @return The array of decoded bytes
     */
    public static byte[] decode(String input, boolean dirty) {
        int[] lookup = {
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0-15
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16-31
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  0, -1, -1, // 32-47
                1,  2,  3,  4,  5,  6,  7,  8,  9, 10, -1, -1, -1, -1, -1, -1, // 48-63
                -1, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // 64-79
                26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, -1, -1, -1, -1, 37, // 80-95
                -1, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, // 96-111
                53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, -1, -1, -1, -1, -1  // 112-127
        };
        byte[] theBytes;
        if (dirty) theBytes = stringToBytes(input.replaceAll("[^0-9a-zA-Z_\\-]", ""));
        else theBytes = stringToBytes(input);
        int inLen = theBytes.length;
        int outLen = inLen - ((inLen + 2) / 4), outPos = 0;
        byte[] output = new byte[outLen];
        int buffer = 0, bitLength = 0, bitShift, value;
        for (byte theByte : theBytes) {
            value = lookup[theByte & 0x7f];
            buffer = (buffer << 6) | value; // append 6 bits every loop
            bitLength += 6;
            if (bitLength >= 8) { // write out 8 bits if there's at least 8 bits in the buffer
                bitShift = bitLength - 8; // number of bits to shift the mask
                output[outPos++] = (byte) ((buffer & (0xff << bitShift)) >> bitShift);
                bitLength -= 8;
            }
        }
        return output;
    }

    /**
     * Decode a base64v2 String into a String.<br>
     *
     * @param input The String to decode
     * @param dirty True if the data may contain non-base64v2 characters (ie: white space, padding)
     *
     * @return The array of decoded bytes
     */
    public static String decodeToString(String input, boolean dirty) {
        return new String(decode(input, dirty));
    }

    /**
     * Encode the current time into a base64v2 String.
     *
     * @return The current time as a base64v2 String
     */
    public static String encodeNow() {
        long value = System.currentTimeMillis();
        int len = 8;
        long mask = 0x100000000000000L;
        while (mask > value) {
            len--;
            mask >>= 8;
        }

        byte date[] = new byte[len];
        for (int c = len - 1; c >= 0; c--) {
            date[c] = (byte) (value & 255);
            value >>= 8;
        }
        return encode(date);
    }

    /**
     * Decode a base64v2 time into a long.
     *
     * @param time The String to decode
     * @param dirty True if the data may contain non-base64v2 characters (ie: white space, padding))
     *
     * @return The time in milliseconds as a long
     */
    public static long decodeTime(String time, boolean dirty) {
        long theTime = 0;
        byte data[] = decode(time, dirty);
        for (byte aByte : data) {
            theTime <<= 8; // shift left one byte
            theTime |= aByte & 255; // OR the byte into the long
        }
        return theTime;
    }

    /**
     * Convert a String to an array of bytes
     *
     * @param input The String to convert
     *
     * @return An array of bytes in UTF-8 format
     */
    public static byte[] stringToBytes(String input) {
        byte[] output = null;
        try {
            output = input.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            output = input.getBytes();
        }
        return output;
    }

    /**
     * Convert an array of bytes into a String
     *
     * @param input An array of bytes in UTF-8 format
     *
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
}





