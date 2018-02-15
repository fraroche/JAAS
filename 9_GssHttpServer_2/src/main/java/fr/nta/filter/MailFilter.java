package fr.nta.filter;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class MailFilter implements Filter {
	public void destroy() {
	}

	public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
		System.out.println("Connection - debut");
		final CharResponseWrapper responseWrapper = new CharResponseWrapper((HttpServletResponse) response);
		chain.doFilter(request, responseWrapper);
		System.out.println(responseWrapper.toString());
		System.out.println("Connection - Fin");
	}

	public void init(final FilterConfig arg0) throws ServletException {
	}

	public static class CharResponseWrapper extends HttpServletResponseWrapper {
		private final CharArrayWriter	output;

		public String toString() {
			return output.toString();
		}
		
		public CharResponseWrapper(final HttpServletResponse response) {
			super(response);
			output = new CharArrayWriter();
		}
	
		public PrintWriter getWriter() {
			return new PrintWriter(output);
		}
	}
}
