package com.course.apisecurity.api.server.sqlinjection;

//@RestController
//@RequestMapping("/api/sqlinjection/safe/v2")
public class JpaCustomerSafeApi {

//	@Autowired
//	private JpaCustomerCrudRepository repository;
//
//	@Autowired
//	private JpaCustomerSafeDAO dao;
//
//	@GetMapping(value = "/customer/{email}")
//	public JpaCustomer findCustomerByEmail(@PathVariable(required = true, name = "email") String email) {
//		var queryResult = repository.findByEmail(email);
//
//		System.out.println(queryResult);
//
//		if (queryResult != null && !queryResult.isEmpty()) {
//			return queryResult.get(0);
//		}
//
//		return null;
//	}
//
//	@GetMapping(value = "/customer")
//	public List<JpaCustomer> findCustomersByGender(
//			@RequestParam(required = true, name = "genderCode") String genderCode) {
//		return dao.findByGender(genderCode);
//	}

}
