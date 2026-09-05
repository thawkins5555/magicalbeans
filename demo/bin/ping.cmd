@set "PY=%NETPATH_DEMO_PYTHON%"
@if not defined PY set "PY=py"
@"%PY%" "%~dp0ping" %*
