import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

public class ShiroTest {
    @Test
    public void get(){
        //加载配置文件
        IniSecurityManagerFactory isma=new IniSecurityManagerFactory("classpath:shiro.ini");
        //通过工厂获取会话
        SecurityManager securityManager = isma.getInstance();
        //将会话管理器设置到运行环境中
        SecurityUtils.setSecurityManager(securityManager);
        //创建主体
        Subject subject=SecurityUtils.getSubject();
        //创建令牌
        UsernamePasswordToken token=new UsernamePasswordToken("zhangsan","123456");
        //主体对令牌进行登录验证
        subject.login(token);
        //判断用户的认证状态，合法性
        System.out.println(subject.isAuthenticated());
        //判断用户有哪些权限
        System.out.println("是否具有创建产品的权限："+subject.isPermitted("product:create"));
        System.out.println("是否具有创建用户的权限："+subject.isPermitted("user:create"));
        //查询用户是否具有某个角色的授权信息
        System.out.println("是否具有授权："+subject.hasRole("admin"));
        System.out.println("是否具有授权："+subject.hasRole("sadmin"));
        subject.logout();
        System.out.println(subject.isAuthenticated());
        //判断用户有哪些权限
        System.out.println("是否具有创建产品的权限："+subject.isPermitted("product:create"));
        System.out.println("是否具有创建用户的权限："+subject.isPermitted("user:create"));
        //查询用户是否具有某个角色的授权信息
        System.out.println("是否具有授权："+subject.hasRole("admin"));
        System.out.println("是否具有授权："+subject.hasRole("sadmin"));
    }
}
