import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SHA256Test {
    private final SHA256 sha256 = new SHA256();

    @Test
    void intAs4Bytes() {
        byte[] actual = sha256.intAs4Bytes(37);
        byte[] expected = new byte[]{0x00, 0x00, 0x00, 0x25};
        assertArrayEquals(expected, actual);

        actual = sha256.intAs4Bytes(257);
        expected = new byte[]{0x00, 0x00, 0x01, 0x01};
        assertArrayEquals(expected, actual);

        actual = sha256.intAs4Bytes(Integer.MAX_VALUE);
        expected = new byte[]{0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        assertArrayEquals(expected, actual);

        actual = sha256.intAs4Bytes(-1);
        expected = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        assertArrayEquals(expected, actual);
    }

    @Test
    void longAs8Bytes() {
        byte[] actual = sha256.longAs8Bytes(Integer.MAX_VALUE * 8L);
        byte[] expected = new byte[]{0x00, 0x00, 0x00, 0x03, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xF8};
        assertArrayEquals(expected, actual);
    }

    @Test
    void fourBytesAsInt() {
        assertEquals(Integer.MAX_VALUE, sha256.fourBytesAsInt(new byte[]{0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}));

        assertEquals(255, sha256.fourBytesAsInt(new byte[]{0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF}));
    }

    @Test
    void calc() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha256.calc("".getBytes()));

        assertEquals("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", sha256.calc("The quick brown fox jumps over the lazy dog".getBytes()));

        assertEquals("cce97087f477acafa60f6e74bfe5dd17d9d099b87fb93a2fb779dbb527a08fe7", sha256.calc("The quick brown fox jumps over the lazy dog".repeat(2).getBytes()));

        assertEquals("44fe939b2ebe138df106f65666e22931c7d6b7b9dea879899cbd83b089c9a7a6", sha256.calc("Пивіт Денис!".getBytes()));
    }
}