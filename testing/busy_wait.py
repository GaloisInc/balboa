import time
from datetime import timedelta
from typing import Callable, Optional


def busy_wait_assert(
    condition: Callable[[], None],
    delay: timedelta = timedelta(seconds=0.1),
    max_times: Optional[int] = 50,
) -> None:
    """
    Keep calling `condition` until it doesn't raise an exception. If, after `max_times` number of
    invocations of `condition` (spaced `delay` apart), `condition` is still raising an exception,
    this function will fail with that exception.

    # Example
    ```python
    def check_file_exists():
        assert os.path.isfile("/tmp/my-extremely-fun-file")
    busy_wait_assert(check_file_exists)
    # Wait a bit for `/tmp/my-extremely-fun-file` to be created.
    ```
    """

    times = 0
    while True:
        try:
            condition()
            return
        except:
            pass
        times += 1
        if max_times is not None and times >= max_times:
            break
        time.sleep(delay.total_seconds())
    # Call condition one final time to trigger the exception.
    condition()
