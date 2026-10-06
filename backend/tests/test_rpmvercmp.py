from vulnex.rpmvercmp import compare_evr, rpmvercmp, split_evr


def _sign(a, b):
    r = rpmvercmp(a, b)
    return (r > 0) - (r < 0)


def test_identical_versions_are_equal():
    assert rpmvercmp("1.0", "1.0") == 0
    assert rpmvercmp("2.0.1a", "2.0.1a") == 0


def test_numeric_and_alpha_segments():
    assert _sign("1.0", "2.0") == -1
    assert _sign("5.5p10", "5.5p1") == 1
    assert _sign("10xyz", "10.1xyz") == -1
    assert _sign("2a", "2.0") == -1
    assert _sign("xyz.4", "8") == -1


def test_leading_zeros_and_equal_values():
    assert rpmvercmp("1.0010", "1.10") == 0
    assert rpmvercmp("1.05", "1.5") == 0
    assert _sign("2.50", "2.5") == 1


def test_separators_ignored_like_rpm():
    assert rpmvercmp("fc4", "fc.4") == 0
    assert rpmvercmp("3.0.0_fc", "3.0.0.fc") == 0
    assert _sign("1.0", "1") == 1
    assert _sign("1", "1.0") == -1


def test_case_sensitivity_matches_rpm():
    assert _sign("FC5", "fc4") == -1


def test_tilde_and_caret():
    assert _sign("1.0~rc1", "1.0") == -1
    assert _sign("1.0", "1.0~rc1") == 1
    assert _sign("1.0^git1", "1.0") == 1
    assert _sign("1.0", "1.0^git1") == -1


def test_split_evr():
    assert split_evr("1.2.3-4").version == "1.2.3"
    assert split_evr("1.2.3-4").release == "4"
    assert split_evr("2:1.2.3-4").epoch == 2
    assert split_evr("1.2.3").release == ""


def test_compare_evr_release_matters():
    assert compare_evr("1.3.1-1", "1.3.1-1") == 0
    assert compare_evr("1.2.13-1", "1.3.1-1") == -1
    # Same version, higher release wins.
    assert compare_evr("8.11.1-11", "8.11.1-10") == 1
    # Epoch dominates.
    assert compare_evr("1:1.0-1", "2.0-1") == 1
