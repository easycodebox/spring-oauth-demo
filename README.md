# spring-oauth-demo

* `hosts`增加以下配置`127.0.0.1 oauth.easycodebox.local`

* 数据库配置
  
  * url : jdbc:mysql://localhost:3306/oauth2
  * username : root
  * password : root

* 表结构

  ```sql
  CREATE TABLE `u_role` (
    `id` int(9) NOT NULL COMMENT '主键',
    `name` varchar(32) NOT NULL COMMENT '角色名',
    `status` int(1) NOT NULL COMMENT '状态 - 0:启用 1:禁用',
    `deleted` int(1) NOT NULL COMMENT '是否删除 - 0:否 1:是',
    `desc` varchar(512) DEFAULT NULL COMMENT '描述',
    `creator` varchar(32) NOT NULL COMMENT '创建人',
    `createTime` datetime NOT NULL COMMENT '创建时间',
    `modifier` varchar(32) NOT NULL COMMENT '修改人',
    `modifyTime` datetime NOT NULL COMMENT '修改时间',
    PRIMARY KEY (`id`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='角色 - 角色';
  
  CREATE TABLE `u_user` (
    `id` varchar(32) NOT NULL COMMENT '主键',
    `userNo` varchar(32) DEFAULT NULL COMMENT '员工编号',
    `username` varchar(32) NOT NULL COMMENT '用户名',
    `nickname` varchar(32) NOT NULL COMMENT '昵称',
    `password` varchar(32) NOT NULL COMMENT '密码',
    `realname` varchar(32) DEFAULT NULL COMMENT '真实姓名',
    `status` int(1) NOT NULL COMMENT '状态 - 0:启用 1:锁定 2:禁用',
    `deleted` int(1) NOT NULL COMMENT '是否删除 - 0:否 1:是',
    `portrait` varchar(512) DEFAULT NULL COMMENT '用户头像',
    `gender` int(1) DEFAULT NULL COMMENT '性别',
    `email` varchar(512) DEFAULT NULL COMMENT '邮箱',
    `mobile` varchar(32) DEFAULT NULL COMMENT '手机号',
    `creator` varchar(32) NOT NULL COMMENT '创建人',
    `createTime` datetime NOT NULL COMMENT '创建时间',
    `modifier` varchar(32) NOT NULL COMMENT '修改人',
    `modifyTime` datetime NOT NULL COMMENT '修改时间',
    PRIMARY KEY (`id`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='用户 - 用户登录后台的用户';
  
  CREATE TABLE `u_user_role` (
    `userId` varchar(32) NOT NULL COMMENT '用户ID',
    `roleId` int(9) NOT NULL COMMENT '角色ID',
    `creator` varchar(32) NOT NULL COMMENT '创建人',
    `createTime` datetime NOT NULL COMMENT '创建时间',
    PRIMARY KEY (`userId`,`roleId`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='用户角色 - 用户与角色的对应关系';
  
  ```