/// Macros for switching betweeen `rayon`'s `ParallelIterator` and vanilla `Iterator`s depending on whether or not the `parallel` feature is enabled.

/// Creates parallel iterator over refs if `parallel` feature is enabled.
/// Additionally, if the object being iterated implements
/// `IndexedParallelIterator`, then one can specify a minimum size for
/// iteration.
#[macro_export]
macro_rules! cfg_iter {
    ($e: expr, $min_len: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.par_iter().with_min_len($min_len);

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.iter();

        result
    }};
    ($e: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.par_iter();

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.iter();

        result
    }};
}

/// Creates parallel iterator over mut refs if `parallel` feature is enabled.
/// Additionally, if the object being iterated implements
/// `IndexedParallelIterator`, then one can specify a minimum size for
/// iteration.
#[macro_export]
macro_rules! cfg_iter_mut {
    ($e: expr, $min_len: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.par_iter_mut().with_min_len($min_len);

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.iter_mut();

        result
    }};
    ($e: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.par_iter_mut();

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.iter_mut();

        result
    }};
}

/// Creates parallel iterator if `parallel` feature is enabled.
/// Additionally, if the object being iterated implements
/// `IndexedParallelIterator`, then one can specify a minimum size for
/// iteration.
#[macro_export]
macro_rules! cfg_into_iter {
    ($e: expr, $min_len: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.into_par_iter().with_min_len($min_len);

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.into_iter();

        result
    }};
    ($e: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.into_par_iter();

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.into_iter();

        result
    }};
}

/// Returns an iterator over `chunk_size` elements of the slice at a
/// time.
#[macro_export]
macro_rules! cfg_chunks {
    ($e: expr, $size: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.par_chunks($size);

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.chunks($size);

        result
    }};
}

/// Returns an iterator over `chunk_size` mutable elements of the slice at a
/// time.
#[macro_export]
macro_rules! cfg_chunks_mut {
    ($e: expr, $size: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.par_chunks_mut($size);

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.chunks_mut($size);

        result
    }};
}

/// Same as `cfg_chunks`, but analogous to `chunks_exact` instead
#[macro_export]
macro_rules! cfg_chunks_exact {
    ($e: expr, $size: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.par_chunks_exact($size);

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.chunks_exact($size);

        result
    }};
}

/// Same as `cfg_chunks`, but analogous to `chunks_exact` instead
#[macro_export]
macro_rules! cfg_chunks_exact_mut {
    ($e: expr, $size: expr) => {{
        #[cfg(any(feature = "parallel", test))]
        let result = $e.par_chunks_exact_mut($size);

        #[cfg(not(any(feature = "parallel", test)))]
        let result = $e.chunks_exact_mut($size);

        result
    }};
}
