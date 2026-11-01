//Created by Salty on 10/31/26.

#ifndef AMLIST_H
#define AMLIST_H

#include "AMBase.h"
#include <stdbool.h>
#include <CoreFoundation/CoreFoundation.h>

#ifdef __cplusplus
extern "C" {
#endif

struct __AMList;
typedef struct __AMList *AMListRef;

/// Creates a list object that automatically filters comments and newlines out.
AM_RETURNS_RETAINED AMListRef AMListCreateWithFileAtURL(CFURLRef URL);

/// Returns the type ID of AMList objects.
AMTypeID AMListGetTypeID(void);

/// Checks if the given string is present in the list.
bool AMListContainsString(AMListRef list, CFStringRef string);

/// Returns the number of items in the list.
CFIndex AMListGetCount(AMListRef list);

/// Checks if the file has been touched since last read. If it has, dumps and re-loads internal list contents.
AMError AMListInvalidateIfNeeded(AMListRef list);

/// Appends one list to the other. Caller is still responsible for freeing the lists where required.
/// @param list The list to append to.
/// @param to_append The list that will be appended to list.
/// @return AMError based on success.
AMError AMListAppendList(AMListRef list, AMListRef to_append);

#ifdef __cplusplus
}
#endif

#endif /* AMLIST_H */
