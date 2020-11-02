import org.apache.commons.lang3.StringUtils;

public class SHA256 {
    //https://en.wikipedia.org/wiki/SHA-2
    public String calc (byte[] message) {
        //Initialize hash values
        //(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
        int h0 = 0x6a09e667;
        int h1 = 0xbb67ae85;
        int h2 = 0x3c6ef372;
        int h3 = 0xa54ff53a;
        int h4 = 0x510e527f;
        int h5 = 0x9b05688c;
        int h6 = 0x1f83d9ab;
        int h7 = 0x5be0cd19;

        //Initialize array of round constants
        //(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
        int[] k = new int[] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        //Pre-processing (Padding)
        long L = message.length * 8L;
        int K = (int) (512 - ((L + 1 + 64) % 512));

        if ((L + 1 + K + 64) % 512 != 0) throw new IllegalStateException("Incorrect K");

        int paddingBytes = (1 + K) / 8;

        byte[] newMessage = new  byte[message.length + paddingBytes + 64 / 8];
        System.arraycopy(message, 0, newMessage, 0, message.length);

        byte[] padding = new byte[paddingBytes];
        padding[0] = (byte) 0b10000000;
        System.arraycopy(padding, 0, newMessage, message.length, padding.length);

        byte[] messageLength = longAs8Bytes(L);
        System.arraycopy(messageLength, 0, newMessage, message.length + padding.length, messageLength.length);

        //Process the message in successive 512-bit chunks
        for (int i = 0; i < newMessage.length; i += 64) {
            byte[] chunk512bit = new byte[64];
            System.arraycopy(newMessage, i, chunk512bit, 0, 64);

            //copy chunk into first 16 words of the message schedule array
            int[] messageScheduleArray = new int[64];
            for (int j = 0; j < 16; j++) {
                byte[] fourBytes = new byte[4];
                System.arraycopy(chunk512bit, j * 4, fourBytes, 0, 4);
                messageScheduleArray[j] = fourBytesAsInt(fourBytes);
            }
            
            //Extend the first 16 words into the remaining 48 words of the message schedule array
            for (int j = 16; j < 64; j++) {
                int s0 = rightRotate(messageScheduleArray[j - 15], 7) ^ rightRotate(messageScheduleArray[j - 15], 18) ^ (messageScheduleArray[j - 15] >>>  3);
                int s1 = rightRotate(messageScheduleArray[j - 2], 17) ^ rightRotate(messageScheduleArray[j - 2],19) ^ (messageScheduleArray[j - 2] >>> 10);
                messageScheduleArray[j] = messageScheduleArray[j - 16] + s0 + messageScheduleArray[j - 7] + s1;
            }

            //Initialize working variables to current hash value
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;
            int f = h5;
            int g = h6;
            int h = h7;

            //Compression function main loop
            for (int j = 0; j < 64; j++) {
                int S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
                int ch = (e & f) ^ ((~e) & g);
                int temp1 = h + S1 + ch + k[j] + messageScheduleArray[j];
                int S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
                int maj = (a & b) ^ (a & c) ^ (b & c);
                int temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            //Add the compressed chunk to the current hash value
            h0 = h0 + a;
            h1 = h1 + b;
            h2 = h2 + c;
            h3 = h3 + d;
            h4 = h4 + e;
            h5 = h5 + f;
            h6 = h6 + g;
            h7 = h7 + h;
        }

        return  StringUtils.leftPad(Integer.toUnsignedString(h0,  16), 8, "0") +
                StringUtils.leftPad(Integer.toUnsignedString(h1,  16), 8, "0") +
                StringUtils.leftPad(Integer.toUnsignedString(h2,  16), 8, "0") +
                StringUtils.leftPad(Integer.toUnsignedString(h3,  16), 8, "0") +
                StringUtils.leftPad(Integer.toUnsignedString(h4,  16), 8, "0") +
                StringUtils.leftPad(Integer.toUnsignedString(h5,  16), 8, "0") +
                StringUtils.leftPad(Integer.toUnsignedString(h6,  16), 8, "0") +
                StringUtils.leftPad(Integer.toUnsignedString(h7,  16), 8, "0");
    }

    byte[] intAs4Bytes (int a) {
        byte[] result = new byte[4];

        int bitmask = 0xFF000000;
        int numberOfPosToShift = 24;
        for (int i = 0; i < 4; i++) {
            byte tmp = (byte) ((a & bitmask) >>> numberOfPosToShift);
            result[i] =  tmp;

            bitmask = bitmask >>> 8;
            numberOfPosToShift -= 8;
        }
        return result;
    }

    byte[] longAs8Bytes (long a) {
        byte[] result = new byte[8];

        long bitmask = 0xFF_00_00_00_00_00_00_00L;
        int numberOfPosToShift = 56;
        for (int i = 0; i < 8; i++) {
            byte tmp = (byte) ((a & bitmask) >>> numberOfPosToShift);
            result[i] =  tmp;

            bitmask = bitmask >>> 8;
            numberOfPosToShift -= 8;
        }
        return result;
    }

    int fourBytesAsInt(byte[] bytes) {
        if (bytes.length != 4) throw new IllegalArgumentException("Array length must be 4");
        int result = 0;

        int numberOfPosToShift = 24;
        for (int i = 0; i < 4; i++) {
            int tmp = Byte.toUnsignedInt(bytes[i]) << numberOfPosToShift;
            result |= tmp;

            numberOfPosToShift -= 8;
        }

        return result;
    }

    int rightRotate (int x, int n) {
        return (x >>> n) | (x << (32-n));
    }
}