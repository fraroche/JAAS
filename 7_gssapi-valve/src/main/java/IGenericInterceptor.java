import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


public interface IGenericInterceptor {
	public void next(ServletRequest request, ServletResponse response) throws Exception;
}