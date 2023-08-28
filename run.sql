SET NAMES utf8mb4;
ALTER table `v3_guild_account_detail_copy`
    add amount_type tinyint(2) DEFAULT 1 COMMENT '1:sum,2:consumable,3:withdrawable,4:backpack';

ALTER table `v3_guild_account_statistics_copy`
    add amount_type tinyint(2) DEFAULT 1 COMMENT '1:sum,2:consumable,3:withdrawable,4:backpack';

ALTER TABLE `v3_guild_account_statistics_copy`
    add UNIQUE KEY `create_time` (`create_time`,`amount_type`) USING BTREE;

ALTER table `v2_system_account_statistics_copy`
    add amount_type tinyint(2) DEFAULT 1 COMMENT '1:sum,2:consumable,3:withdrawable,4:backpack';

ALTER TABLE `v2_system_account_statistics_copy`
    add UNIQUE KEY `fi_account_id` (`fi_account_id`,`create_time`,`amount_type`) USING BTREE;

ALTER table `finance_data_calculation_sum_copy`
    add amount_type tinyint(2) DEFAULT 1 COMMENT '1:sum,2:consumable,3:withdrawable,4:backpack';

ALTER TABLE `finance_data_calculation_sum_copy`
    add UNIQUE KEY `type` (`type`,`uuid`,`calculation_time`,`amount_type`) USING BTREE;

ALTER table `finance_data_calculation_pledge2023_07`
    add amount_type tinyint(2) DEFAULT 1 COMMENT '1:sum,2:consumable,3:withdrawable,4:backpack';

ALTER TABLE `finance_data_calculation_pledge2023_07`
    add KEY `type` (`type`,`calculation_time`,`amount_type`) USING BTREE;

ALTER TABLE `finance_data_calculation_pledge2023_07`
    add KEY `uuid` (`uuid`,`calculation_time`,`amount_type`) USING BTREE;

ALTER table `finance_data_calculation_pledge2023_08`
    add amount_type tinyint(2) DEFAULT 1 COMMENT '1:sum,2:consumable,3:withdrawable,4:backpack';

ALTER TABLE `finance_data_calculation_pledge2023_08`
    add KEY `type` (`type`,`calculation_time`,`amount_type`) USING BTREE;

ALTER TABLE `finance_data_calculation_pledge2023_08`
    add KEY `uuid` (`uuid`,`calculation_time`,`amount_type`) USING BTREE;

