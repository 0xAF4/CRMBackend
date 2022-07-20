CREATE DATABASE my_crm;

CREATE TABLE `my_activated_keys` (
  `user_id` int NOT NULL,
  `soft_id` int NOT NULL,
  `mkey` varchar(64) NOT NULL,
  `time` int NOT NULL,
  `activate_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `mkey` (`mkey`)
)

CREATE TABLE `my_ips` (
  `user_id` int NOT NULL,
  `software` varchar(64) NOT NULL,
  `ip` varchar(32) NOT NULL,
  `login_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP
)

CREATE TABLE `my_keys` (
  `soft_id` int NOT NULL,
  `mkey` varchar(64) NOT NULL,
  `time` int NOT NULL,
  UNIQUE KEY `mkey` (`mkey`)
)

CREATE TABLE `my_softwares` (
  `soft_id` int NOT NULL AUTO_INCREMENT,
  `soft_name` varchar(64) NOT NULL,
  `version` varchar(64) NOT NULL,
  `payload` MEDIUMTEXT,  
  PRIMARY KEY (`soft_id`),
  UNIQUE KEY `soft_name` (`soft_name`)
)

CREATE TABLE `my_softwares_1` (
  `user_id` int NOT NULL,
  `exp_time` varchar(64) NOT NULL,
  UNIQUE KEY `user_id` (`user_id`)
)

CREATE TABLE `my_users` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `login` varchar(64) NOT NULL,
  `password` varchar(64) NOT NULL,
  `hwid` varchar(64) NOT NULL,
  `token` varchar(255) DEFAULT NULL,
  `reg_ip` varchar(32) DEFAULT NULL,
  `reg_software` varchar(64) DEFAULT NULL,
  `reg_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `hwid` (`hwid`),
  UNIQUE KEY `login` (`login`),
  UNIQUE KEY `reg_ip` (`reg_ip`),
  UNIQUE KEY `reg_ip_2` (`reg_ip`)
)