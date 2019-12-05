package shiro;

import entity.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class UserRealm extends AuthorizingRealm {
    /**
     * 认证 令牌：用户名，密码
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //获取令牌里面的用户名
        String username = (String) authenticationToken.getPrincipal();
        //获取令牌里面的密码
        String password=new String((char[])authenticationToken.getCredentials());
        User user = new User();
        user.setUsername("admin");
        user.setPassword("123456");
        user.setStatus("1");
        if(!username.equals(user.getUsername())){
            throw  new UnknownAccountException("用户名不存在！");
        }
        else if(!password.equals(user.getPassword())){
            throw new IncorrectCredentialsException("密码错误！");
        }else if("0".equals(user.getStatus())){
            throw new LockedAccountException("用户被锁定！");
        }
        return new SimpleAuthenticationInfo(user,password,getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }
}
