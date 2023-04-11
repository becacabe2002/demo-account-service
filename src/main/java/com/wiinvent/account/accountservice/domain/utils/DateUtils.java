package com.wiinvent.account.accountservice.domain.utils;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAdjusters;
import java.util.Date;

public class DateUtils {

    private static final ZoneId DEFAULT_ZONE_ID = ZoneId.of("UTC");
//  private static final ZoneId ZONE_ID_UTC = ZoneId.of("UTC");

    public static String ZONE_MYANMAR = "Asia/Yangon";

    public static LocalDateTime now() {
        return LocalDateTime.now(DEFAULT_ZONE_ID);
    }

    public static long nowInMillis() {
        return LocalDateTime.now(DEFAULT_ZONE_ID).toInstant(ZoneOffset.UTC).toEpochMilli();
    }

    public static String nowString() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime dateTime = LocalDateTime.now(DEFAULT_ZONE_ID);
        return dateTime.format(formatter);
    }

    public static LocalDateTime convertMMToUtc(LocalDateTime utcTime) {
        return utcTime.atZone(ZoneId.of(ZONE_MYANMAR))
                .withZoneSameInstant(DEFAULT_ZONE_ID)
                .toLocalDateTime();
    }

    public static Date asDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(DEFAULT_ZONE_ID).toInstant());
    }

    public static LocalDateTime startOfDay() {
        return LocalDateTime.now(DEFAULT_ZONE_ID).with(LocalTime.MIN);
    }

    public static LocalDateTime startOfDay(LocalDateTime dateTime) {
        return dateTime.with(LocalTime.MIN);
    }


    public static String startOfDayString() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime dateTime = LocalDateTime.now(DEFAULT_ZONE_ID).with(LocalTime.MIN);
        return dateTime.format(formatter);
    }

    public static String startOfDayString(LocalDateTime dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        dateTime.with(LocalTime.MIN);
        return dateTime.format(formatter);
    }

    public static LocalDateTime endOfDay() {
        return LocalDateTime.now(DEFAULT_ZONE_ID).with(LocalTime.MAX);
    }

    public static LocalDateTime endOfDay(LocalDateTime dateTime) {
        return dateTime.with(LocalTime.MAX);
    }

    public static String endOfDayString() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime dateTime = LocalDateTime.now(DEFAULT_ZONE_ID).with(LocalTime.MAX);
        return dateTime.format(formatter);
    }

    public static String endOfDayString(LocalDateTime dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        dateTime.with(LocalTime.MAX);
        return dateTime.format(formatter);
    }

    public static boolean belongsToCurrentDay(final LocalDateTime localDateTime) {
        return localDateTime.isAfter(startOfDay()) && localDateTime.isBefore(endOfDay());
    }

    // note that week starts with Monday
    public static LocalDateTime startOfWeek(Integer value) {
        return LocalDateTime.now(DEFAULT_ZONE_ID)
                .minusWeeks(value)
                .with(LocalTime.MIN)
                .with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
    }

    // note that week ends with Sunday
    public static LocalDateTime endOfWeek(Integer value) {
        return LocalDateTime.now(DEFAULT_ZONE_ID)
                .minusWeeks(value)
                .with(LocalTime.MAX)
                .with(TemporalAdjusters.nextOrSame(DayOfWeek.SUNDAY));
    }

    public static LocalDateTime startOfMonth(Integer value) {
        return LocalDateTime.now(DEFAULT_ZONE_ID)
                .minusMonths(value)
                .with(LocalTime.MIN)
                .with(TemporalAdjusters.firstDayOfMonth());
    }

    public static LocalDateTime endOfMonth(Integer value) {
        return LocalDateTime.now(DEFAULT_ZONE_ID)
                .minusMonths(value)
                .with(LocalTime.MAX)
                .with(TemporalAdjusters.lastDayOfMonth());
    }

    public static long toMills(final LocalDateTime localDateTime) {
        return localDateTime.atZone(DEFAULT_ZONE_ID).toInstant().toEpochMilli();
    }

    public static Date toDate(final LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(DEFAULT_ZONE_ID).toInstant());
    }

    public static String toString(final LocalDateTime localDateTime) {
        return localDateTime.format(DateTimeFormatter.ISO_DATE_TIME);
    }

    public static String dateTimeToString(String dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime datetime = LocalDateTime.parse(dateTime, formatter);
        return datetime.format(formatter);
    }

    public static String convertLocalDateToString(LocalDate date) {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("dd-LL-yyyy");
        return date.format(dateTimeFormatter);
    }

    public static String convertLocalDateTimeToString(LocalDateTime dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return dateTime.format(formatter);
    }

    public static Long getCurrentTime(){
        return System.currentTimeMillis();
    }
}

