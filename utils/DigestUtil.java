package cn.wl.code;

import org.apache.commons.lang3.time.DateFormatUtils;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;

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
     * @param seconds 有效期（秒）
     * @return
     */
    public static String encode(String str, Integer... seconds) {
        return encode(str.getBytes(), seconds);
    }

    /**
     * 自定义加密
     *
     * @param bytes   内容
     * @param seconds 有效期（秒）
     * @return
     */
    public static String encode(byte[] bytes, Integer... seconds) {
        if (seconds == null || seconds.length == 0) {
            return Base64.getEncoder().encodeToString($(bytes));
        }

        long second = seconds[0];
        LocalDateTime nowDate = LocalDateTime.now();

        long key = 0;
        LocalDateTime newDate = null;
        StringBuilder sb = new StringBuilder();
        if (second < 60) {
            // 有效期（秒）
            sb.append(nowDate.getYear());
            key = nowDate.getMonthValue();
            sb = key > 9 ? sb.append(key) : sb.append("0").append(key);
            key = nowDate.getDayOfMonth();
            sb = key > 9 ? sb.append(key) : sb.append("0").append(key);
            key = nowDate.getHour();
            sb = key > 9 ? sb.append(key) : sb.append("0").append(key);
            key = nowDate.getMinute();
            sb = key > 9 ? sb.append(key) : sb.append("0").append(key);
            key = Long.parseLong(sb.toString());
            newDate = nowDate.plusMinutes(1).withSecond(0);
        } else if (second < 3600) {
            // 有效期（分钟）
            sb.append(nowDate.getYear());
            key = nowDate.getMonthValue();
            sb = key > 9 ? sb.append(key) : sb.append("0").append(key);
            key = nowDate.getDayOfMonth();
            sb = key > 9 ? sb.append(key) : sb.append("0").append(key);
            key = nowDate.getHour();
            sb = key > 9 ? sb.append(key) : sb.append("0").append(key);
            key = Long.parseLong(sb.toString());
            newDate = nowDate.plusHours(1).withMinute(0).withSecond(0);
        } else if (second < 86400) {
            // 有效期（小时）
            sb.append(nowDate.getYear());
            key = nowDate.getMonthValue();
            sb = key > 9 ? sb.append(key) : sb.append("0").append(key);
            key = nowDate.getDayOfMonth();
            sb = key > 9 ? sb.append(key) : sb.append("0").append(key);
            key = Long.parseLong(sb.toString());
            newDate = nowDate.plusDays(1).withHour(0).withMinute(0).withSecond(0);
        } else {
            // 有效期（天）
            key = nowDate.getYear();
            newDate = nowDate.plusYears(1).withMonth(1).withDayOfMonth(1).withHour(0).withMinute(0).withSecond(0);
        }

        long secret = (newDate.toEpochSecond(ZoneOffset.UTC)) - second - (nowDate.toEpochSecond(ZoneOffset.UTC));
        Long[] keys = new Long[KEYS.length];
        keys[0] = (KEYS[0] & key) + secret + second;
        System.arraycopy(KEYS, 1, keys, 1, keys.length - 1);
        String code = Base64.getEncoder().encodeToString($(bytes, keys));
        return code + encode(String.format("%09d", secret));
    }

    /**
     * 自定义解密
     *
     * @param str     内容
     * @param seconds 有效期（秒）
     * @return
     */
    public static byte[] decode(String str, Integer... seconds) {
        if (seconds == null || seconds.length == 0) {
            return $(Base64.getDecoder().decode(str));
        }

        try {
            int second = seconds[0];
            String code = str.substring(0, str.length() - 12);
            long secret = Long.parseLong(new String(decode(str.substring(str.length() - 12))));

            String pattern = null;
            if (second < 60) {
                pattern = "yyyyMMddHHmm";
            } else if (second < 3600) {
                pattern = "yyyyMMddHH";
            } else if (second < 86400) {
                pattern = "yyyyMMdd";
            } else {
                pattern = "yyyy";
            }

            long key = Long.parseLong(DateFormatUtils.format(((secret * 1000) + new Date().getTime()), pattern));

            Long[] keys = new Long[KEYS.length];
            keys[0] = (KEYS[0] & key) + secret + second;
            System.arraycopy(KEYS, 1, keys, 1, keys.length - 1);
            return $(Base64.getDecoder().decode(code), keys);
        } catch (Exception e) {
            return $(Base64.getDecoder().decode(str));
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
