package fr.nta.foo;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class for Servlet: InitServlet
 *
 */
public class InitServlet extends javax.servlet.http.HttpServlet implements javax.servlet.Servlet {
	static final long	serialVersionUID	= 1L;

	public InitServlet() {
		super();
	}

	protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	protected void doPost(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
		System.out.println("toto");
		response.getWriter().print("<b>Your in !!!</b>");
		response.getWriter().print("<a href=\""+ request.getContextPath()+"/index.html" +"\">go</a>");
		System.out.println("titi");
	}

	public void init() throws ServletException {
		System.out.println("Init");
		super.init();
	}
}