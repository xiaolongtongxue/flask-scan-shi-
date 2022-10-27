-- 建库
CREATE DATABASE `flask_scan`;
use `flask_scan`;
-- 建表 users
drop table if exists users;
create table users
(
    id       varchar(16)   not null,
    username varchar(20)   not null,
    level    int default 5 not null,
    passwd   char(32)      not null
);
create unique index users_id_uindex
    on users (id);
create unique index users_username_uindex
    on users (username);
alter table users
    add constraint users_pk
        primary key (id);
-- 建表 ports_scan
drop table if exists host_scan;
create table host_scan
(
    scan_time timestamp default NOW() not null,
    scan_id   varchar(17)             not null,
    userid    varchar(16)             not null,
    byway     int                     not null,
    hosts     varchar(256)            null,
    End       longtext                null,
    ErrorCode int                     null
);
create unique index host_scan_scan_id_uindex
    on host_scan (scan_id);
alter table host_scan
    add constraint host_scan_pk
        primary key (scan_id);
-- 建表 hosts_scan
drop table if exists ports_scan;
create table ports_scan
(
    scan_time timestamp default NOW() not null,
    scan_id   varchar(17)             not null,
    userid    varchar(16)             not null,
    byway     int                     not null,
    hosts     varchar(256)            not null,
    ports     varchar(256)            null,
    End       longtext                null,
    ErrorCode int                     null
);
create unique index scapy_scan_scan_id_uindex
    on ports_scan (scan_id);
alter table ports_scan
    add constraint scapy_scan_pk
        primary key (scan_id);

# INSERT INTO `flask_scan`.users(id, username, level, passwd) VALUE ("16668558718369", "admin", 1, "67270dc97c302a79fa87817fd01873cc");