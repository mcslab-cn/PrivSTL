package cn.edu.buaa.crypto.access;

/**
 * Created by Weiran Liu on 2016/7/18.
 *
 * Unsatisfied access control exception, used for access control policy.
 */

public class UnsatisfiedAccessControlException extends Exception {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public UnsatisfiedAccessControlException(String message){
        super(message);
    }
}
