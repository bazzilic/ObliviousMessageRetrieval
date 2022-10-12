#pragma once

template <typename T>
inline std::string formatDuration(T timeunit)
{
    std::chrono::nanoseconds ns = std::chrono::duration_cast<std::chrono::nanoseconds>(timeunit);
    std::ostringstream os;
    int precision_count = 2;
    bool foundNonZero = false;
    os.fill('0');
    typedef std::chrono::duration<int, std::ratio<86400 * 365>> years;
    const auto y = std::chrono::duration_cast<years>(ns);
    if (y.count())
    {
        foundNonZero = true;
        precision_count--;
        os << y.count() << "y";
        ns -= y;
    }
    typedef std::chrono::duration<int, std::ratio<86400>> days;
    const auto d = std::chrono::duration_cast<days>(ns);
    if (d.count())
    {
        if(foundNonZero)
            os << ":";
        foundNonZero = true;
        precision_count--;
        os << d.count() << "d";
        ns -= d;
    }
    const auto h = std::chrono::duration_cast<std::chrono::hours>(ns);
    if (h.count() || foundNonZero)
    {
        if(foundNonZero)
            os << ":";
        foundNonZero = true;
        precision_count--;
        os << h.count() << "h";
        ns -= h;
    }
    const auto m = std::chrono::duration_cast<std::chrono::minutes>(ns);
    if ((m.count() || foundNonZero) && (precision_count-- > 0))
    {
        if(foundNonZero)
            os << ":";
        foundNonZero = true;
        os << m.count() << "m";
        ns -= m;
    }
    const auto s = std::chrono::duration_cast<std::chrono::seconds>(ns);
    if ((s.count() || foundNonZero) && (precision_count-- > 0))
    {
        if(foundNonZero)
            os << ":";
        foundNonZero = true;
        os << s.count() << "s";
        ns -= s;
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(ns);
    if ((ms.count() || foundNonZero) && (precision_count-- > 0))
    {
        if (foundNonZero)
            os << ":" << std::setw(3);
        foundNonZero = true;
        os << ms.count() << "ms";
        ns -= ms;
        foundNonZero = true;
    }
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(ns);
    if ((us.count() || foundNonZero) && (precision_count-- > 0))
    {
        if (foundNonZero)
            os << ":" << std::setw(3);
        foundNonZero = true;
        os << us.count() << "us";
        ns -= us;
    }
    if (precision_count-- > 0) {
        if (foundNonZero)
            os << ":" << std::setw(3);
        os << ns.count() << "ns";
    }
    return os.str();
}