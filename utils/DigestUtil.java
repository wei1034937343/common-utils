package cn.wl.code;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Function;

/**
 * 自定义加密解密类 Created by 韦武良 on 2016年10月17日.
 */
public class DigestUtil {
    // 默认密钥组
    private static final Long[] KEYS = {0xFFL, 99L, 077L};

    /**
     * 自定义加密
     *
     * @param str     内容
     * @param seconds 1年内有效期（秒）
     * @return
     */
    public static String encode(String str, Integer... seconds) {
        return encode(str.getBytes(), seconds);
    }

    /**
     * 自定义加密
     *
     * @param bytes   内容
     * @param seconds 1年内有效期（秒）
     * @return
     */
    public static String encode(byte[] bytes, Integer... seconds) {
        Function<byte[], String> fun = (d) -> Base64.getEncoder().encodeToString(d);
        if (seconds == null || seconds.length == 0) {
            return fun.apply($(bytes));
        }

        LocalDateTime nowDate = LocalDateTime.now();
        LocalDateTime newDate = nowDate.plusYears(1).withMonth(1).withDayOfMonth(1).withHour(0).withMinute(0).withSecond(0);

        long second = seconds[0];
        long key = nowDate.getYear();
        long secret = (newDate.toEpochSecond(ZoneOffset.UTC)) - second - (nowDate.toEpochSecond(ZoneOffset.UTC));

        long k1 = (KEYS[0] & key) * 1000000 + (KEYS[0] & secret) * 1000 + (KEYS[0] & second);
        Long[] keys = Arrays.asList(KEYS).stream().map(d -> d ^ k1).toArray(Long[]::new);
        String code = Base64.getEncoder().encodeToString($(bytes, keys));

        long k2 = seconds[0].longValue();
        keys = Arrays.asList(KEYS).stream().map(d -> d & k2).toArray(Long[]::new);
        return code + fun.apply($(String.format("%09d", secret).getBytes(), keys));
    }

    /**
     * 自定义解密
     *
     * @param str     内容
     * @param seconds 1年内有效期（秒）
     * @return
     */
    public static byte[] decode(String str, Integer... seconds) {
        Function<String, byte[]> fun = (d) -> Base64.getDecoder().decode(d);
        if (seconds == null || seconds.length == 0) {
            return $(fun.apply(str));
        }

        try {
            long k2 = seconds[0].longValue();
            Long[] keys = Arrays.asList(KEYS).stream().map(d -> d & k2).toArray(Long[]::new);
            String code = str.substring(0, str.length() - 12);

            long second = seconds[0];
            long secret = Long.parseLong(new String($(fun.apply(str.substring(code.length())), keys)));
            long key = LocalDateTime.now().plusSeconds(secret).getYear();

            long k1 = (KEYS[0] & key) * 1000000 + (KEYS[0] & secret) * 1000 + (KEYS[0] & second);
            keys = Arrays.asList(KEYS).stream().map(d -> d ^ k1).toArray(Long[]::new);
            return $(Base64.getDecoder().decode(code), keys);
        } catch (Exception e) {
            return $(fun.apply(str));
        }
    }

    /**
     * 自定义异或加密
     *
     * @param bytes
     * @return
     */
    private static byte[] $(byte[] bytes, Long... keys) {
        if (keys == null || keys.length == 0) {
            keys = KEYS;
        }
        for (int i = 0; i < bytes.length; ++i) {
            bytes[i] ^= keys[i % keys.length];
        }
        return bytes;
    }
}
