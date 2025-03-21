package helpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class HTTPHelpers {

    /**
     * <a href="http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html">Source</a>
     */
    public byte[] decompress(byte[] data, boolean gzip) throws DataFormatException {
        if (data == null || data.length == 0) {
            return new byte[0];
        }
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length)) {
            Inflater inflater = new Inflater(gzip);
            inflater.setInput(data);
            byte[] buffer = new byte[1024];
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                outputStream.write(buffer, 0, count);
            }
            byte[] output = outputStream.toByteArray();
            inflater.end();
            return output;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * <a href="http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html">Source</a>
     */
    public byte[] compress(byte[] data, boolean gzip) {
        if (data == null || data.length == 0) {
            return new byte[0];
        }
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length)) {
            Deflater deflater = new Deflater(5, gzip);
            deflater.setInput(data);
            deflater.finish();
            byte[] buffer = new byte[1024];
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                outputStream.write(buffer, 0, count);
            }
            byte[] output = outputStream.toByteArray();
            deflater.end();
            return output;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }


}
